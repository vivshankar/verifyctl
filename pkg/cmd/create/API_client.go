package create

import (
	"encoding/json"
	"io"
	"os"

	"github.com/ibm-security-verify/verifyctl/pkg/cmd/resource"
	"github.com/ibm-security-verify/verifyctl/pkg/config"
	"github.com/ibm-security-verify/verifyctl/pkg/module"
	"github.com/ibm-security-verify/verifyctl/pkg/module/security"
	cmdutil "github.com/ibm-security-verify/verifyctl/pkg/util/cmd"
	"github.com/ibm-security-verify/verifyctl/pkg/util/templates"
	"gopkg.in/yaml.v3"

	"github.com/spf13/cobra"
)

const (
	apiClientUsage         = "apiclient [options]"
	apiClientMessagePrefix = "CreateApiClient"
	apiClientEntitlements  = "Manage API Clients"
	apiClientResourceName  = "apiclient"
)

var (
	apiClientShortDesc = cmdutil.TranslateShortDesc(apiClientMessagePrefix, "Options to create an API client.")

	apiClientLongDesc = templates.LongDesc(cmdutil.TranslateLongDesc(apiClientMessagePrefix, `
        Options to create an API client.
 
        API clients on Verify require specific entitlements, so ensure that the application or API client used
        with the 'auth' command has the required entitlements.
 
        An empty resource file can be generated using:
 
            verifyctl create apiclient --boilerplate
 
        You can check required entitlements by running:
 
            verifyctl create apiclient --entitlements`))

	apiClientExamples = templates.Examples(cmdutil.TranslateExamples(apiClientMessagePrefix, `
        # Create an empty API client resource.
        verifyctl create apiclient --boilerplate
 
        # Create an API client using a JSON file.
        verifyctl create apiclient -f=./apiclient.json`))
)

type apiClientOptions struct {
	options
	config *config.CLIConfig
}

func newAPIClientCommand(config *config.CLIConfig, streams io.ReadWriter) *cobra.Command {
	o := &apiClientOptions{
		config: config,
	}

	cmd := &cobra.Command{
		Use:                   apiClientUsage,
		Short:                 apiClientShortDesc,
		Long:                  apiClientLongDesc,
		Example:               apiClientExamples,
		DisableFlagsInUseLine: true,
		Run: func(cmd *cobra.Command, args []string) {
			cmdutil.ExitOnError(cmd, o.Complete(cmd, args))
			cmdutil.ExitOnError(cmd, o.Validate(cmd, args))
			cmdutil.ExitOnError(cmd, o.Run(cmd, args))
		},
	}

	cmd.SetOut(streams)
	cmd.SetErr(streams)
	cmd.SetIn(streams)

	o.AddFlags(cmd)

	return cmd
}

func (o *apiClientOptions) AddFlags(cmd *cobra.Command) {
	o.addCommonFlags(cmd, apiClientResourceName)
	cmd.Flags().StringVarP(&o.file, "file", "f", "", "Path to the yaml file containing API client data.")
}

func (o *apiClientOptions) Complete(cmd *cobra.Command, args []string) error {
	return nil
}

func (o *apiClientOptions) Validate(cmd *cobra.Command, args []string) error {
	if o.entitlements || o.boilerplate {
		return nil
	}

	if len(o.file) == 0 {
		return module.MakeSimpleError("The 'file' option is required if no other options are used.")
	}
	return nil
}

func (o *apiClientOptions) Run(cmd *cobra.Command, args []string) error {
	if o.entitlements {
		cmdutil.WriteString(cmd, entitlementsMessage+"  "+apiClientEntitlements)
		return nil
	}

	if o.boilerplate {
		resourceObj := &resource.ResourceObject{
			Kind:       resource.ResourceTypePrefix + "ApiClient",
			APIVersion: "1.0",
			Data:       &security.Client{},
		}

		cmdutil.WriteAsYAML(cmd, resourceObj, cmd.OutOrStdout())
		return nil
	}

	auth, err := o.config.GetCurrentAuth()
	if err != nil {
		return err
	}

	return o.createAPIClient(cmd, auth)
}

func (o *apiClientOptions) createAPIClient(cmd *cobra.Command, auth *config.AuthConfig) error {
	ctx := cmd.Context()
	vc := config.GetVerifyContext(ctx)

	b, err := os.ReadFile(o.file)
	if err != nil {
		vc.Logger.Errorf("unable to read file; filename=%s, err=%v", o.file, err)
		return err
	}

	return o.createAPIClientWithData(cmd, auth, b)
}

func (o *apiClientOptions) createAPIClientWithData(cmd *cobra.Command, auth *config.AuthConfig, data []byte) error {
	ctx := cmd.Context()
	vc := config.GetVerifyContext(ctx)

	apiclient := &security.Client{}
	if err := yaml.Unmarshal(data, &apiclient); err != nil {
		vc.Logger.Errorf("unable to unmarshal API client; err=%v", err)
		return err
	}

	if apiclient.ClientName == "" {
		return module.MakeSimpleError("clientName is required")
	}
	if len(apiclient.Entitlements) == 0 {
		return module.MakeSimpleError("entitlements list is required")
	}

	client := security.NewAPIClient()
	resourceURI, err := client.CreateAPIClient(ctx, auth, apiclient)
	if err != nil {
		vc.Logger.Errorf("failed to create API client; err=%v", err)
		return err
	}

	cmdutil.WriteString(cmd, "Resource created: "+resourceURI)
	return nil
}

func (o *apiClientOptions) createAPIClientFromDataMap(cmd *cobra.Command, auth *config.AuthConfig, data map[string]interface{}) error {
	ctx := cmd.Context()
	vc := config.GetVerifyContext(ctx)

	// Convert map data to JSON
	apiclient := &security.Client{}
	b, err := json.Marshal(data)
	if err != nil {
		vc.Logger.Errorf("failed to marshal data; err=%v", err)
		return err
	}

	if err := json.Unmarshal(b, apiclient); err != nil {
		vc.Logger.Errorf("unable to unmarshal data to API client; err=%v", err)
		return err
	}

	// Validate required fields
	if apiclient.ClientName == "" {
		return module.MakeSimpleError("clientName is required")
	}
	if len(apiclient.Entitlements) == 0 {
		return module.MakeSimpleError("entitlements list is required")
	}

	// Create API client
	client := security.NewAPIClient()
	resourceURI, err := client.CreateApiClient(ctx, auth, apiclient)
	if err != nil {
		vc.Logger.Errorf("failed to create API client; err=%v", err)
		return err
	}

	// Directly return the created resource URI
	cmdutil.WriteString(cmd, "Resource created: "+resourceURI)
	return nil
}
