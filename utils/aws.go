package utils

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ses"
)

func CreateSESClient() *ses.Client {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion("us-east-1")) // Replace with your AWS region
	if err != nil {
		panic(err)
	}
	return ses.NewFromConfig(cfg)
}
