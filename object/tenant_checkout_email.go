// Copyright 2026 The Casdoor Authors. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package object

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/beego/beego/v2/core/logs"
	"github.com/casdoor/casdoor/i18n"
	"github.com/casdoor/casdoor/pp"
	"github.com/casdoor/casdoor/util"
)

// The terminal-state check under the Group lock elects the sole transaction
// winner. Notify only after commit succeeds; a duplicate callback never reaches
// this Created -> Paid branch. Process death after commit can lose the email.
func finishGroupPayment(commit func() error, payment *Payment, previous pp.PaymentState, notify func(*Payment)) (*Payment, error) {
	if err := commit(); err != nil {
		return nil, err
	}
	if previous == pp.PaymentStateCreated && payment.State == pp.PaymentStatePaid {
		notify(payment)
	}
	return payment, nil
}

type groupPaymentEmailContext struct {
	payer    *User
	provider *Provider
	sender   string
}

func loadGroupPaymentEmailContext(payment *Payment) (*groupPaymentEmailContext, error) {
	config, err := getTenantCheckoutConfig()
	if err != nil || config.application == "" || payment.Owner != config.organization {
		return nil, ErrTenantCheckoutRequired
	}
	// Read the current persisted payer, never callback or return-URL contact data.
	payer, err := GetUser(util.GetId(payment.Owner, payment.User))
	if err != nil {
		return nil, err
	}
	application, err := GetApplication(util.GetId("admin", strings.TrimPrefix(config.application, "app/")))
	if err != nil {
		return nil, err
	}
	if application == nil || application.Organization != payment.Owner {
		return nil, fmt.Errorf("payment email application unavailable")
	}
	provider, err := application.GetEmailProvider("Payment")
	if err != nil {
		return nil, err
	}
	return &groupPaymentEmailContext{payer: payer, provider: provider, sender: application.DisplayName}, nil
}

// Dependencies are explicit only to exercise this side effect without a DB or
// external email in unit tests. There is no retry or durable delivery state.
func attemptGroupPaymentEmail(payment *Payment, load func(*Payment) (*groupPaymentEmailContext, error), send func(*Provider, string, string, []string, string) error) (status string) {
	status = "failed"
	defer func() {
		if recover() != nil {
			status = "failed"
		}
	}()
	if payment == nil || payment.Group == "" || payment.State != pp.PaymentStatePaid {
		return "skipped"
	}
	context, err := load(payment)
	if err != nil {
		return "unavailable"
	}
	if context == nil || context.payer == nil || context.payer.Owner != payment.Owner || context.payer.Name != payment.User || context.payer.IsDeleted || context.payer.IsForbidden || !context.payer.EmailVerified || !util.IsEmailValid(context.payer.Email) {
		return "skipped"
	}
	if context.provider == nil || context.provider.Owner != payment.Owner || context.provider.Category != "Email" || context.provider.State == "Disabled" {
		return "unavailable"
	}
	title := i18n.Translate(context.payer.Language, "payment:Payment completed")
	content := i18n.Translate(context.payer.Language, "payment:Your subscription payment has completed.")
	if payment.Type == "Dummy" {
		title = i18n.Translate(context.payer.Language, "payment:Test payment completed")
		content = i18n.Translate(context.payer.Language, "payment:Your test subscription payment has completed. No money was collected.")
	}
	if err := send(context.provider, title, content, []string{context.payer.Email}, context.sender); err != nil {
		return "failed"
	}
	return "sent"
}

func notifyGroupPaymentEmail(payment *Payment) {
	status := attemptGroupPaymentEmail(payment, loadGroupPaymentEmailContext, SendEmail)
	// Never log recipient, message body, credentials, or provider exception text.
	eventID := sha256.Sum256([]byte(payment.GetId()))
	logs.Info("event=tenant_payment_email event_id=%x time=%s status=%s", eventID, util.GetCurrentTime(), status)
}
