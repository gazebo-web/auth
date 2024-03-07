package authentication

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

// GCPIamServiceAccountAccessToken is a higher order function that returns an
// AccessTokenAuthentication func.
// The resulting function allows verifying access tokens provided by GCP IAM for
// service accounts.
func GCPIamServiceAccountAccessToken(project, serviceAccountName string) AccessTokenAuthentication {
	svc, err := newIamService()
	if err != nil {
		return nil
	}
	return func(ctx context.Context, token string) error {
		permissionCall := newTestPermissionCall(svc, project, serviceAccountName, token)
		res, err := permissionCall.Do()
		if err != nil {
			return err
		}
		if len(res.Permissions) == 0 {
			return errors.New("missing permissions")
		}
		return nil
	}
}

// generateIamServiceAccountResourceName generates a resource name for testing
// the available IAM permissions in a service account.
func generateIamServiceAccountResourceName(project string, name string) string {
	return fmt.Sprintf("projects/%s/serviceAccounts/%s@%s.iam.gserviceaccount.com", project, name, project)
}

// newIamService initializes a new IAM service that allows performing requests
// to Google Cloud Platform API.
func newIamService() (*iam.Service, error) {
	return iam.NewService(context.Background(), option.WithHTTPClient(&http.Client{
		Timeout: 30 * time.Second,
	}))
}

// newTestPermissionCall initializes a new iam.ProjectsServiceAccountsTestIamPermissionsCall.
//
// The resulting object will allow calling Google Cloud Platform in behave of
// the access token provided as an argument.
//
// This access token should be limited in scope, as to allow the token to act as
// the service account identified by serviceAccountName that lives in the given
// project.
func newTestPermissionCall(svc *iam.Service, project string, serviceAccountName string, token string) *iam.ProjectsServiceAccountsTestIamPermissionsCall {
	call := svc.Projects.ServiceAccounts.TestIamPermissions(
		generateIamServiceAccountResourceName(project, serviceAccountName),
		newTestPermissionsRequest(),
	)
	call = setPermissionCallAccessToken(call, token)
	return call
}

// setPermissionCallAccessToken sets the provided access token as authentication
// mechanism to the given iam.ProjectsServiceAccountsTestIamPermissionsCall.
func setPermissionCallAccessToken(permissionCall *iam.ProjectsServiceAccountsTestIamPermissionsCall, token string) *iam.ProjectsServiceAccountsTestIamPermissionsCall {
	permissionCall.Header().Set("Authorization", fmt.Sprintf("Bearer %s", token))
	return permissionCall
}

// newTestPermissionsRequest initializes a new iam.TestIamPermissionsRequest
// that will be used to perform access token verification.
func newTestPermissionsRequest() *iam.TestIamPermissionsRequest {
	return &iam.TestIamPermissionsRequest{
		Permissions: []string{"iam.serviceAccounts.actAs"},
	}
}
