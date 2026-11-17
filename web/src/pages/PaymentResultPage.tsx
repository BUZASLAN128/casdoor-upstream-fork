import * as React from "react";
import i18next from "i18next";
import {AlertTriangle, CheckCircle2, Info, XCircle} from "lucide-react";
import {useLocation, useNavigate, useParams, useSearchParams} from "react-router-dom";
import {Button} from "@/components/ui/button";
import {Loading} from "@/components/common/Loading";
import {useAccount} from "@/hooks/use-account";
import * as PaymentBackend from "@/backend/PaymentBackend";
import * as PricingBackend from "@/backend/PricingBackend";
import * as SubscriptionBackend from "@/backend/SubscriptionBackend";
import * as UserBackend from "@/backend/UserBackend";
import * as Setting from "@/lib/setting";

/** Payment types the frontend nudges with /api/notify-payment while they are pending. */
const NOTIFIABLE = ["PayPal", "Stripe", "AirWallex", "Alipay", "WeChat Pay", "Balance", "Dummy"];

// The only result a signed-out payer is sent back to after login; LoginPage's TENANT_RESULT_RETURN is the same pattern.
const TENANT_RESULT = /^\/buy-plan\/[^/?#]+\/[^/?#]+\/result\?payment=payment_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

type Status = "success" | "info" | "warning" | "error";

function Result({status, title, subTitle, extra}: {status: Status; title: React.ReactNode; subTitle?: React.ReactNode; extra?: React.ReactNode}) {
  const Icon = {success: CheckCircle2, info: Info, warning: AlertTriangle, error: XCircle}[status];
  const color = {
    success: "text-emerald-500",
    info: "text-sky-500",
    warning: "text-amber-500",
    error: "text-destructive",
  }[status];

  return (
    <div className="mx-auto flex max-w-2xl flex-col items-center gap-4 py-16 text-center">
      <Icon className={`h-16 w-16 ${color}`} />
      <h1 className="text-xl font-semibold">{title}</h1>
      {subTitle ? <p className="text-muted-foreground">{subTitle}</p> : null}
      {extra ? <div className="flex flex-wrap justify-center gap-2 pt-2">{extra}</div> : null}
    </div>
  );
}

/**
 * The page a payment provider returns to. Ported from web/src/PaymentResultPage.js:
 * while the payment is still "Created" it polls once a second, calling
 * /api/notify-payment first for the providers that need the nudge.
 */
export default function PaymentResultPage() {
  const params = useParams();
  const [search] = useSearchParams();
  const location = useLocation();
  const navigate = useNavigate();
  const {account, loading} = useAccount();

  const owner = params.organizationName ?? params.owner ?? "";
  const pricingName = params.pricingName ?? "";
  const subscriptionName = search.get("subscription");

  // /buy-plan/:owner/:pricingName/result?payment= is where a tenant checkout returns, outside the console
  const [paymentName, setPaymentName] = React.useState(params.paymentName ?? (pricingName ? search.get("payment") ?? "" : ""));
  const [payment, setPayment] = React.useState<any>(null);
  const [user, setUser] = React.useState<any>(null);
  const [nonce, setNonce] = React.useState(0);
  const [failed, setFailed] = React.useState(false);

  const here = location.pathname + location.search;
  const loginReturn = !loading && account === null && TENANT_RESULT.test(here);

  React.useEffect(() => {
    if (loginReturn) {
      sessionStorage.setItem("from", here);
      navigate(`/login/${encodeURIComponent(owner)}`, {replace: true});
    }
  }, [loginReturn, here, navigate, owner]);

  // resolve the payment name from the subscription when arriving from /buy-plan
  React.useEffect(() => {
    if (!owner || !pricingName || !subscriptionName) {
      return;
    }
    let cancelled = false;
    (async() => {
      try {
        const pricingRes = await PricingBackend.getPricing(owner, pricingName);
        if (pricingRes.status !== "ok") {
          throw new Error(pricingRes.msg);
        }
        const subscriptionRes = await SubscriptionBackend.getSubscription(owner, subscriptionName);
        if (subscriptionRes.status !== "ok") {
          throw new Error(subscriptionRes.msg);
        }
        if (!cancelled) {
          setPaymentName(subscriptionRes.data.payment);
        }
      } catch (err: any) {
        Setting.showMessage("error", err.message);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [owner, pricingName, subscriptionName]);

  React.useEffect(() => {
    if (!owner || !paymentName || loading || loginReturn) {
      return;
    }
    let cancelled = false;
    let timer: number | undefined;

    PaymentBackend.getPayment(owner, paymentName)
      .then((res: any) => {
        if (cancelled) {
          return;
        }
        // another account's payment (or none) is refused, never polled or notified
        if (res.status !== "ok" || !res.data) {
          setFailed(true);
          return;
        }
        const next = res.data;
        setPayment(next);
        if (account && next.owner === account.owner && next.user === account.name && sessionStorage.getItem("from") === here) {
          sessionStorage.removeItem("from");
        }

        if (next.state === "Created") {
          timer = window.setTimeout(async() => {
            if (NOTIFIABLE.includes(next.type)) {
              await PaymentBackend.notifyPayment(owner, paymentName);
            }
            setNonce((n) => n + 1);
          }, 1000);
        } else if (next.state === "Paid" && account) {
          UserBackend.getUser(account.owner, account.name).then((userRes: any) => {
            if (!cancelled && userRes.status === "ok") {
              setUser(userRes.data);
            }
          });
        }
      });

    return () => {
      cancelled = true;
      if (timer !== undefined) {
        window.clearTimeout(timer);
      }
    };
  }, [owner, paymentName, nonce, account, loading, loginReturn, here]);

  // a console-disabled payer cannot open the order pages; the organization's own site is the way back
  const consoleClosed = account?.organization?.disableConsole && !Setting.isLocalAdminUser(account);
  const homeUrl = String(account?.organization?.websiteUrl ?? "");
  const backToSite = /^https?:\/\//.test(homeUrl) ? (
    <Button onClick={() => Setting.goToLink(homeUrl)}>{i18next.t("payment:Back to Cerberus")}</Button>
  ) : null;
  const orderList = (
    <Button variant="outline" onClick={() => navigate("/orders")}>
      {i18next.t("order:Return to Order List")}
    </Button>
  );

  if (failed) {
    return (
      <Result
        status="error"
        title={i18next.t("general:Sorry, you do not have permission to access this page or logged in status invalid.")}
        extra={account ? (consoleClosed ? backToSite : orderList) : null}
      />
    );
  }

  if (payment === null) {
    return <Loading />;
  }

  const goToViewOrder = () => {
    if (payment.order) {
      navigate(`/orders/${payment.owner}/${payment.order}/pay`);
    } else {
      Setting.showMessage("error", i18next.t("order:Order not found"));
    }
  };

  const actions = consoleClosed ? backToSite : (
    <>
      <Button onClick={goToViewOrder}>{i18next.t("order:View Order")}</Button>
      {orderList}
    </>
  );
  const subTitle = consoleClosed
    ? i18next.t("payment:The plan status shows under Service summary on your Cerberus Dashboard")
    : i18next.t("payment:You can view your order details or return to the order list");
  const currency = Setting.getCurrencyText(payment.currency);

  if (payment.state === "Paid") {
    if (payment.isRecharge) {
      return (
        <Result
          status="success"
          title={i18next.t("payment:Recharged successfully")}
          subTitle={`${i18next.t("payment:You have successfully recharged")} ${payment.price} ${currency}, ${i18next.t("payment:Your current balance is")} ${user?.balance} ${currency}`}
          extra={actions}
        />
      );
    }
    return (
      <Result
        status="success"
        title={`${i18next.t("payment:You have successfully completed the payment")}: ${payment.productsDisplayName}`}
        subTitle={subTitle}
        extra={actions}
      />
    );
  }

  if (payment.state === "Created") {
    return (
      <Result
        status="info"
        title={`${i18next.t("payment:The payment is still under processing")}: ${payment.productsDisplayName}, ${i18next.t("payment:the current state is")}: ${payment.state}, ${i18next.t("payment:please wait for a few seconds...")}`}
        subTitle={subTitle}
        extra={<Loading />}
      />
    );
  }

  if (payment.state === "Canceled" || payment.state === "Timeout") {
    const title = payment.state === "Canceled"
      ? i18next.t("payment:The payment has been canceled")
      : i18next.t("payment:The payment has timed out");
    return (
      <Result
        status="warning"
        title={`${title}: ${payment.productsDisplayName}, ${i18next.t("payment:the current state is")}: ${payment.state}`}
        subTitle={subTitle}
        extra={actions}
      />
    );
  }

  return (
    <Result
      status="error"
      title={`${i18next.t("payment:The payment has failed")}: ${payment.productsDisplayName}, ${i18next.t("payment:the current state is")}: ${payment.state}`}
      subTitle={`${i18next.t("payment:Failed reason")}: ${payment.message}`}
      extra={actions}
    />
  );
}
