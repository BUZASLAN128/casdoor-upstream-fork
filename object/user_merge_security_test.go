package object

import (
	"os"
	"strings"
	"testing"
)

func TestCerberusSecuritySoftDeletedOrganizationsCannotMergeAccounts(t *testing.T) {
	if err := getUserMergeDeletionPolicyError(&Organization{EnableSoftDeletion: true}); err == nil {
		t.Fatal("soft-deletion organization allowed a non-atomic account merge")
	}
	if err := getUserMergeDeletionPolicyError(&Organization{}); err != nil {
		t.Fatalf("hard-delete organization was rejected: %v", err)
	}
	if err := getUserMergeDeletionPolicyError(nil); err == nil {
		t.Fatal("missing organization did not fail closed")
	}
}

func TestCerberusSecurityMergeUsesPermanentDeletionAfterPolicyGuard(t *testing.T) {
	source, err := os.ReadFile("user_merge.go")
	if err != nil {
		t.Fatalf("read user_merge.go: %v", err)
	}
	text := string(source)
	guard := strings.Index(text, "checkUserMergeDeletionPolicy(from.Owner)")
	deletion := strings.Index(text, "deleteUserPermanentlyForMerge(from)")
	if guard < 0 || deletion < 0 || guard > deletion {
		t.Fatal("merge must guard the deletion policy before permanently retiring the source account")
	}
}
