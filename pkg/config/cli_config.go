package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	errorsx "github.com/ibm-verify/verify-sdk-go/pkg/core/errors"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
	"gopkg.in/yaml.v3"
)

const (
	apiVersion  = "1.0"
	kind        = "Config"
	fileName    = "config"
	defaultPerm = os.ModePerm
)

type CLIConfig struct {
	APIVersion    string        `yaml:"apiVersion"`
	Kind          string        `yaml:"kind"`
	CurrentTenant string        `yaml:"tenant"`
	Auth          []*AuthConfig `yaml:"auth"`
}

type AuthConfig struct {
	Tenant string `yaml:"tenant"`
	Token  string `yaml:"token"`
	User   bool   `yaml:"isUser"`
}

func NewCLIConfig() *CLIConfig {
	return &CLIConfig{
		APIVersion: apiVersion,
		Kind:       kind,
		Auth:       []*AuthConfig{},
	}
}

func (o *CLIConfig) AddAuth(config *AuthConfig) {
	// check if it already exists and replace if so
	for _, c := range o.Auth {
		if c.Tenant == config.Tenant {
			// replace
			c.Merge(config)
			return
		}
	}

	// add it to the auth list
	o.Auth = append(o.Auth, config)
}

func (o *CLIConfig) SetCurrentTenant(tenant string) {
	o.CurrentTenant = tenant
}

func (o *CLIConfig) LoadFromFile() (*CLIConfig, error) {
	configDir, err := cmdutil.GetDir()
	if err != nil {
		return o, err
	}

	configFile := filepath.Join(configDir, fileName)
	if _, err := os.Stat(configFile); errors.Is(err, os.ErrNotExist) {
		// do nothing. the file will get created when something needs to be added.
		return o, nil
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return o, err
	}

	if err = yaml.Unmarshal(data, o); err != nil {
		return o, err
	}

	return o, nil
}

func (o *CLIConfig) PersistFile() (*CLIConfig, error) {
	data, err := yaml.Marshal(o)
	if err != nil {
		return o, err
	}

	configDir, err := cmdutil.CreateOrGetDir()
	if err != nil {
		return o, err
	}

	configFile := filepath.Join(configDir, fileName)
	if err = os.WriteFile(configFile, data, defaultPerm); err != nil {
		return o, err
	}

	return o, nil
}

func (o *CLIConfig) GetCurrentAuth() (*AuthConfig, error) {
	for _, c := range o.Auth {
		if c.Tenant == o.CurrentTenant {
			return c, nil
		}
	}

	return nil, errorsx.G11NError("No login session available. Use:\n  verifyctl login -h")
}

func (o *CLIConfig) SetAuthToContext(ctx context.Context) (*AuthConfig, error) {
	auth, err := o.GetCurrentAuth()
	if err != nil {
		return nil, err
	}

	// hydrate the verify context with current auth information
	vc := contextx.GetVerifyContext(ctx)
	vc.Tenant = auth.Tenant
	vc.Token = auth.Token

	return auth, nil
}

func (o *AuthConfig) Merge(c *AuthConfig) {
	o.Tenant = c.Tenant
	o.Token = c.Token
	o.User = c.User
}
