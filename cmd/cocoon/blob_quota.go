package main

import (
	"encoding/json"

	"github.com/haileyok/cocoon/server"
	"github.com/urfave/cli/v2"
)

var runBlobQuotaBackfill = &cli.Command{
	Name:  "blob-quota-backfill",
	Usage: "Account one bounded batch of legacy payloads; repeat until Complete is true (no object deletion)",
	Flags: []cli.Flag{&cli.IntFlag{Name: "batch", Value: 100, Usage: "Maximum metadata rows and unknown objects per invocation (1-100)"}},
	Action: func(cmd *cli.Context) error {
		database, err := newDb(cmd)
		if err != nil {
			return err
		}
		pool, err := database.DB()
		if err != nil {
			return err
		}
		defer pool.Close()
		progress, err := server.BackfillBlobQuota(cmd.Context, database, &server.S3Config{
			BlobstoreEnabled: cmd.Bool("s3-blobstore-enabled"),
			Region:           cmd.String("s3-region"), Bucket: cmd.String("s3-bucket"), Endpoint: cmd.String("s3-endpoint"),
			AccessKey: cmd.String("s3-access-key"), SecretKey: cmd.String("s3-secret-key"),
		}, cmd.Int("batch"))
		if err != nil {
			return err
		}
		return json.NewEncoder(cmd.App.Writer).Encode(progress)
	},
}
