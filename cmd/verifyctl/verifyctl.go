package main

import (
	"context"
	"fmt"
	"io"
	"os"

	contextx "github.com/ibm-verify/verify-sdk-go/pkg/core/context"
	"github.com/ibm-verify/verifyctl/pkg/cmd"
	"github.com/ibm-verify/verifyctl/pkg/config"
	cmdutil "github.com/ibm-verify/verifyctl/pkg/util/cmd"
)

func main() {

	logger, w, err := cmdutil.NewLogger()
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	//Close log writer when exit
	defer func() {
		if file, ok := w.(*os.File); ok {
			_ = file.Sync()
			file.Close()
		} else if handler, ok := w.(io.Closer); ok {
			handler.Close()
		}
	}()

	ctx, err := contextx.NewContextWithVerifyContext(context.Background(), logger)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	config, err := config.NewCLIConfig().LoadFromFile()
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	verifyCmd := cmd.NewRootCmd(config, nil)
	cmdutil.ExitOnError(verifyCmd, verifyCmd.ExecuteContext(ctx))
}
