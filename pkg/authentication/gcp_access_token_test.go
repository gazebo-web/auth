package authentication

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/api/iam/v1"
)

func TestSetPermissionCallAccessToken(t *testing.T) {
	call := &iam.ProjectsServiceAccountsTestIamPermissionsCall{}
	call = setPermissionCallAccessToken(call, "test")
	assert.Equal(t, "Bearer test", call.Header().Get("Authorization"))
}

func TestGenerateIamServiceAccountResourceName(t *testing.T) {
	const project = "project-test"
	const name = "my-test-name"
	result := generateIamServiceAccountResourceName(project, name)
	assert.Equal(t, "projects/project-test/serviceAccounts/my-test-name@project-test.iam.gserviceaccount.com", result)
}

func TestNewTestPermissionsRequest(t *testing.T) {
	req := newTestPermissionsRequest()
	assert.Len(t, req.Permissions, 1)
	assert.Contains(t, req.Permissions, "iam.serviceAccounts.actAs")
}
