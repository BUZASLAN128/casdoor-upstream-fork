package object

import "testing"

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
