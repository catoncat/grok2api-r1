package media

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const s3WriteProbeTTL = time.Minute

type s3API interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

// S3Store implements MediaObjectStorage using an S3-compatible endpoint
// (Tencent COS, AWS S3, MinIO, etc.). Images are stored as objects with
// a configurable prefix and served via a public base URL.
type S3Store struct {
	client        s3API
	bucket        string
	prefix        string
	publicBaseURL string // e.g. https://bucket.cos.region.myqcloud.com
	healthMu      sync.Mutex
	healthAt      time.Time
}

type S3Config struct {
	Endpoint        string // e.g. https://cos.na-siliconvalley.myqcloud.com
	Region          string // e.g. na-siliconvalley
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	Prefix          string // e.g. images/
	PublicBaseURL   string // e.g. https://bucket.cos.region.myqcloud.com
}

func NewS3Store(cfg S3Config) (*S3Store, error) {
	if strings.TrimSpace(cfg.Bucket) == "" {
		return nil, fmt.Errorf("S3 存储桶名不能为空")
	}
	region := strings.TrimSpace(cfg.Region)
	if region == "" {
		region = "auto"
	}
	awsCfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, "")),
	)
	if err != nil {
		return nil, fmt.Errorf("加载 S3 配置: %w", err)
	}
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if ep := strings.TrimSpace(cfg.Endpoint); ep != "" {
			o.BaseEndpoint = aws.String(ep)
		}
		// COS requires virtual-hosted style (bucket.cos.region.myqcloud.com)
		o.UsePathStyle = false
	})
	return &S3Store{
		client:        client,
		bucket:        cfg.Bucket,
		prefix:        strings.TrimSuffix(strings.TrimSpace(cfg.Prefix), "/"),
		publicBaseURL: strings.TrimRight(strings.TrimSpace(cfg.PublicBaseURL), "/"),
	}, nil
}

func (s *S3Store) SaveImage(ctx context.Context, id, mimeType string, data []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	extension, ok := imageExtension(mimeType)
	if !ok || len(id) < 2 {
		return "", fmt.Errorf("图片存储参数无效")
	}
	storageKey := s.key(id[:2], id+extension)
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(s.fullKey(storageKey)),
		Body:        bytes.NewReader(data),
		ContentType: aws.String(mimeType),
		// public-read so clients can download without going through the VPS
		ACL: types.ObjectCannedACLPublicRead,
	})
	if err != nil {
		return "", fmt.Errorf("上传图片到 S3: %w", err)
	}
	// Return a storage key relative to the bucket root (same format as LocalStore)
	return storageKey, nil
}

func (s *S3Store) Open(ctx context.Context, storageKey string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	resp, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.fullKey(storageKey)),
	})
	if err != nil {
		var nfe *types.NoSuchKey
		if errors.As(err, &nfe) {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("从 S3 打开图片: %w", err)
	}
	return resp.Body, nil
}

func (s *S3Store) Delete(ctx context.Context, storageKey string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s.fullKey(storageKey)),
	})
	if err != nil {
		return fmt.Errorf("从 S3 删除图片: %w", err)
	}
	return nil
}

// PublicURL returns the direct S3/COS URL for serving images without going through the gateway.
func (s *S3Store) PublicURL(storageKey string) string {
	if s.publicBaseURL == "" {
		return ""
	}
	return s.publicBaseURL + "/" + s.fullKey(storageKey)
}

func (s *S3Store) key(dir, name string) string {
	// Return storageKey in the same format as LocalStore for DB compatibility
	return "images/" + dir + "/" + name
}

func (s *S3Store) fullKey(storageKey string) string {
	if s.prefix == "" {
		return storageKey
	}
	return s.prefix + "/" + storageKey
}

// Ping verifies the same write, public ACL, and delete permissions used by media delivery.
func (s *S3Store) Ping(ctx context.Context) error {
	s.healthMu.Lock()
	if !s.healthAt.IsZero() && time.Since(s.healthAt) < s3WriteProbeTTL {
		s.healthMu.Unlock()
		return nil
	}
	s.healthMu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	key := s.fullKey(s.key(".grok2api-health", "write-probe"))
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader(nil),
		ACL:    types.ObjectCannedACLPublicRead,
	})
	if err != nil {
		return fmt.Errorf("S3 写入探测失败: %w", err)
	}
	if _, err = s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)}); err != nil {
		return fmt.Errorf("S3 清理探测对象失败: %w", err)
	}
	s.healthMu.Lock()
	s.healthAt = time.Now()
	s.healthMu.Unlock()
	return nil
}
