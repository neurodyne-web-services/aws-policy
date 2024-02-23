package policy_test

import (
	"encoding/json"
	"fmt"
	"testing"

	policy "github.com/neurodyne-web-services/aws-policy"
)

var validatePolicies = []struct {
	inputPolicy  []byte
	outputPolicy policy.Policy
	parsed       error
}{
	{
		inputPolicy: []byte(`
	{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Action": [
				  "sts:AssumeRole"
				],
				"Resource": [
				  "arn:aws:iam::99999999999:role/admin"
				]
			}
		]
	}		
	`), outputPolicy: policy.Policy{
			Version: "2012-10-17",
			ID:      "",
			Statements: []policy.Statement{
				{
					StatementID: "",
					Effect:      "Allow",
					Principal: map[string][]string{
						"AWS": {"arn:aws:iam::1234567890:root"},
					},
					NotPrincipal: map[string][]string{},
					Action: []string{
						"sts:AssumeRole",
					},
					NotAction:   []string{},
					Resource:    []string{},
					NotResource: []string{},
					Condition:   []string{},
				}}}, parsed: nil,
	},
	{
		inputPolicy: []byte(`
			{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": [
							"athena:*"
						],
						"Resource": [
							"arn:aws:athena:eu-west-5:*:workgroup/AthenaWorkGroup"
						]
					},
					{
						"Effect": "Allow",
						"Action": [
							"glue:GetDatabase",
							"glue:GetDatabases",
							"glue:CreateTable",
							"glue:UpdateTable",
							"glue:GetTable",
							"glue:GetTables",
							"glue:GetPartition",
							"glue:GetPartitions",
							"glue:BatchGetPartition",
							"glue:GetCatalogImportStatus"
						],
						"Resource": [
							"*"
						]
					},
					{
						"Effect": "Allow",
						"Action": [
							"s3:GetObject",
							"s3:ListBucket",
							"s3:ListBucketMultipartUploads",
							"s3:ListMultipartUploadParts",
							"s3:AbortMultipartUpload",
							"s3:CreateBucket",
							"s3:ListAllMyBuckets",
							"s3:GetBucketLocation"
						],
						"Resource": [
							"arn:aws:s3:::bucket1",
							"arn:aws:s3:::bucket1/*"
						]
					}
				]
			}		
			`),
		outputPolicy: policy.Policy{
			Version: "2012-10-17",
			ID:      "",
			Statements: []policy.Statement{
				{
					Effect: "Allow",
					Action: []string{"athena:*"},
					Resource: []string{
						"arn:aws:athena:eu-west-5:*:workgroup/AthenaWorkGroup",
					},
					NotResource: []string{},
					Condition:   []string{},
				}, {
					Effect: "Allow",
					Action: []string{
						"glue:GetDatabase",
						"glue:GetDatabases",
						"glue:CreateTable",
						"glue:UpdateTable",
						"glue:GetTable",
						"glue:GetTables",
						"glue:GetPartition",
						"glue:GetPartitions",
						"glue:BatchGetPartition",
						"glue:GetCatalogImportStatus"},
					Resource:    []string{"*"},
					NotResource: []string{},
					Condition:   []string{},
				}, {
					Effect: "Allow",
					Action: []string{
						"s3:GetObject",
						"s3:ListBucket",
						"s3:ListBucketMultipartUploads",
						"s3:ListMultipartUploadParts",
						"s3:AbortMultipartUpload",
						"s3:CreateBucket",
						"s3:ListAllMyBuckets",
						"s3:GetBucketLocation"},
					Resource: []string{
						"arn:aws:s3:::bucket1",
						"arn:aws:s3:::bucket1/*",
					},
					NotResource: []string{},
					Condition:   []string{},
				}}}, parsed: nil,
	}}

func TestParsePolicies(t *testing.T) {

	for _, test := range validatePolicies {
		var policy policy.Policy
		t.Run(string(test.inputPolicy), func(t *testing.T) {
			got := policy.UnmarshalJSON(test.inputPolicy)
			if got != test.parsed {
				t.Errorf("Expected: %v, got: %v", test.parsed, got)
			}
		})
	}
}

func Test_aws_policies(t *testing.T) {
	t.Run("ABAC - parse AWS S3 policy", func(t *testing.T) {
		var policy policy.Policy

		str := `
		{
			"Id": "Policy1708701122507",
			"Version": "2012-10-17",
			"Statement": [
				{
					"Sid": "Stmt1708701120289",
					"Action": [
						"s3:CreateAccessGrant",
						"s3:CreateAccessGrantsInstance",
						"s3:CreateAccessGrantsLocation",
						"s3:CreateAccessPoint"
					],
					"Effect": "Allow",
					"Resource": "arn:aws:s3:::my-buck/mykey",
					"Principal": {
						"AWS": ["nws"]
					}
				}
			]
		}`

		err := json.Unmarshal([]byte(str), &policy)
		if err != nil {
			t.Error(err)
		}

		for _, v := range policy.Statements {
			fmt.Printf("*** sid: %s, action: %s, effect: %s, resource: %s\n", v.StatementID, v.Action, v.Effect, v.Resource)
		}
	})

	t.Run("ABAC - parse AWS SQS policy", func(t *testing.T) {
		var policy policy.Policy

		str := `
		{
			"Version": "2012-10-17",
			"Statement": [
				{
					"Sid": "Stmt1708688460854",
					"Action": ["sqs:AddPermission", "sqs:DeleteMessage", "sqs:DeleteQueue"],
					"Effect": "Allow",
					"Resource": "arn:aws:sqs:000111:my-queue"
				},
				{
					"Sid": "Stmt1708688672846",
					"Action": "kms:*",
					"Effect": "Allow",
					"Resource": "arn:aws:kms:ru-msk-0:111222:mykey/001122"
				}
			]
		}`

		err := json.Unmarshal([]byte(str), &policy)
		if err != nil {
			t.Error(err)
		}

		for _, v := range policy.Statements {
			fmt.Printf("*** sid: %s, action: %s, effect: %s, resource: %s\n", v.StatementID, v.Action, v.Effect, v.Resource)
		}
	})
}
