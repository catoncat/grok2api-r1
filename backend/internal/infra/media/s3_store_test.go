package media

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type probeS3Client struct {
	putInput    *s3.PutObjectInput
	deleteInput *s3.DeleteObjectInput
	putCalls    int
	deleteCalls int
	putErr      error
	deleteErr   error
}

func (c *probeS3Client) PutObject(_ context.Context, input *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	c.putInput = input
	c.putCalls++
	return &s3.PutObjectOutput{}, c.putErr
}

func (c *probeS3Client) GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return nil, errors.New("unexpected GetObject")
}

func (c *probeS3Client) DeleteObject(_ context.Context, input *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	c.deleteInput = input
	c.deleteCalls++
	return &s3.DeleteObjectOutput{}, c.deleteErr
}

func TestS3PingVerifiesPublicWriteAndDeleteAndCachesSuccess(t *testing.T) {
	client := &probeS3Client{}
	store := &S3Store{client: client, bucket: "media", prefix: "prod"}
	if err := store.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.putCalls != 1 || client.deleteCalls != 1 {
		t.Fatalf("probe calls put=%d delete=%d", client.putCalls, client.deleteCalls)
	}
	if client.putInput.ACL != types.ObjectCannedACLPublicRead {
		t.Fatalf("probe ACL = %q", client.putInput.ACL)
	}
	if client.putInput.Key == nil || *client.putInput.Key != "prod/images/.grok2api-health/write-probe" {
		t.Fatalf("put key = %v", client.putInput.Key)
	}
	if client.deleteInput.Key == nil || *client.deleteInput.Key != *client.putInput.Key {
		t.Fatalf("delete key = %v", client.deleteInput.Key)
	}
	body, err := io.ReadAll(client.putInput.Body)
	if err != nil || len(body) != 0 {
		t.Fatalf("probe body = %q, err=%v", body, err)
	}
	if err := store.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	if client.putCalls != 1 || client.deleteCalls != 1 {
		t.Fatalf("cached probe repeated: put=%d delete=%d", client.putCalls, client.deleteCalls)
	}
}

func TestS3SaveImageUsesConfiguredPrefixAndReturnsRelativeKey(t *testing.T) {
	client := &probeS3Client{}
	store := &S3Store{client: client, bucket: "media", prefix: "prod"}
	storageKey, err := store.SaveImage(context.Background(), "img_abcdefghijklmnopqrstuvwxyz", "image/png", []byte("image"))
	if err != nil {
		t.Fatal(err)
	}
	if storageKey != "images/im/img_abcdefghijklmnopqrstuvwxyz.png" {
		t.Fatalf("storage key = %q", storageKey)
	}
	if client.putInput.Key == nil || *client.putInput.Key != "prod/"+storageKey {
		t.Fatalf("put key = %v", client.putInput.Key)
	}
	if client.putInput.ACL != types.ObjectCannedACLPublicRead {
		t.Fatalf("image ACL = %q", client.putInput.ACL)
	}
}

func TestS3PingFailsWhenPublicWriteOrCleanupFails(t *testing.T) {
	tests := []struct {
		name        string
		client      *probeS3Client
		wantDeletes int
	}{
		{name: "write", client: &probeS3Client{putErr: errors.New("write denied")}},
		{name: "delete", client: &probeS3Client{deleteErr: errors.New("delete denied")}, wantDeletes: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &S3Store{client: test.client, bucket: "media"}
			if err := store.Ping(context.Background()); err == nil {
				t.Fatal("probe unexpectedly succeeded")
			}
			if test.client.deleteCalls != test.wantDeletes {
				t.Fatalf("delete calls = %d, want %d", test.client.deleteCalls, test.wantDeletes)
			}
		})
	}
}
