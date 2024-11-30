package pkg

import (
	"bytes"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/spf13/viper"
)

func InitAWS() (*session.Session, error) {
	// Initialize AWS session
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(viper.GetString("AWS_REGION")),
		Credentials: credentials.NewStaticCredentials(viper.GetString("AWS_ACCESS_KEY"), viper.GetString("AWS_SECRET_KEY"), ""),
	})
	if err != nil {
		fmt.Println("Failed to initialize AWS session:", err)
		return nil, err
	}

	return sess, err
}

func InitS3(sess *session.Session) (*s3.S3, error) {
	// Initialize S3 client
	s3Client := s3.New(sess)
	return s3Client, nil
}

func CreateBucketFolderEmailUser(s3Client *s3.S3, reqEmail string) error {
	// Create the folder/prefix in S3
	bucketName := viper.GetString("S3_BUCKET_NAME") // "ses-mailsaja-received"
	folderKey := fmt.Sprintf("%s/", reqEmail)       // e.g., "person11@mailsaja.com/"

	// Upload an empty object to create the folder
	_, err := s3Client.PutObject(&s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(folderKey),
		Body:   bytes.NewReader([]byte{}),
	})
	if err != nil {
		fmt.Println("Failed to create bucket folder:", err)
		return err
	}

	_, err = s3Client.PutObject(&s3.PutObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String(reqEmail + "/"),
	})
	if err != nil {
		fmt.Println("Failed to create bucket folder:", err)
		return err
	}

	return nil
}

func DeleteS3FolderContents(s3Client *s3.S3, bucket, prefix string) error {
	// List all objects with the prefix
	listInput := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	}

	// Delete objects in batches
	return s3Client.ListObjectsV2Pages(listInput, func(page *s3.ListObjectsV2Output, lastPage bool) bool {
		var objects []*s3.ObjectIdentifier
		for _, obj := range page.Contents {
			objects = append(objects, &s3.ObjectIdentifier{Key: obj.Key})
		}

		if len(objects) > 0 {
			deleteInput := &s3.DeleteObjectsInput{
				Bucket: aws.String(bucket),
				Delete: &s3.Delete{
					Objects: objects,
					Quiet:   aws.Bool(true),
				},
			}

			_, err := s3Client.DeleteObjects(deleteInput)
			if err != nil {
				fmt.Printf("Failed to delete objects: %v\n", err)
			}
		}

		return !lastPage
	})
}
