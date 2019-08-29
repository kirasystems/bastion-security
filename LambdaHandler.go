// (C) Copyright 2019 Kira Systems
//
// This file contains the necessary code for an AWS lambda function
// that, when run, inspects a designated security group and deletes
// from it rules that
//
//   a) have timestamps at the end of their description text that are
//   older than the expiry duration relative to the point at which the
//   code is invoked; or
//
//   b) have missing or invalid timestamps in their descriptions.
//
// The security group is designated via the `SG_ID` environment
// variable, and the expiry duration is similarly supplied via the
// `EXPIRY` environment variable.  The syntax for the duration is
// specified in the Go language's time.Duration documentation, but
// obvious permutations of things like "15m" and "1h10m30s" ought to
// work.  The environment variable for the actual Lambda function are
// specified in the CloudFormation template.
//

package main

import (
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"

	"github.com/aws/aws-lambda-go/lambda"
)

// The usual main function.  Presently it has a simple check to see if
// it's being run from the commandline for debugging --- to set it in
// that mode, supply any argument on the commandline (its presence is
// what is checked-for, not its value).
func main() {
	if len(os.Args) == 1 {
		lambda.Start(LambdaHandler)
	} else {
		RunFromCommand()
	}
}

// Primary function to set this code up to run as a Lambda function in
// AWS.  Reads in the parameters from environment variables, creates
// and AWS API session from environment-attached credentials, and then
// calls the main logic.
func LambdaHandler() error {
	sg_id := os.Getenv("SG_ID")
	log.Printf("Starting cleanup for group %s", sg_id)

	expiry := os.Getenv("EXPIRY")
	duration, err := time.ParseDuration(expiry)
	if err != nil {
		log.Printf("Expiry string %s not a valid duration (see Golang time.Duration docs)", expiry)
		return nil
	}

	svc := ec2.New(session.Must(session.NewSession()))

	err = cleanSecurityGroup(svc, aws.String(sg_id), duration)

	log.Printf("Finished cleanup for group %s", sg_id)

	return err
}

// Secondary function to allow this code to be called on the
// commandline.  Security group, expiry, region, and AWS credential
// profile are all presently hardcoded.
func RunFromCommand() {
	sg_id := "sg-00112233445566778" // replace these...
	expiry := "1m"
	profile := "default"
	region := "ca-central-1"

	log.Printf("[Command Line Invocation] Starting cleanup for group %s", sg_id)

	duration, err := time.ParseDuration(expiry)
	if err != nil {
		log.Printf("Expiry string %s not a valid duration (see Golang time.Duration docs)", expiry)
		return
	}

	sess := session.Must(session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewSharedCredentials("", profile),
	}))
	svc := ec2.New(sess)

	cleanSecurityGroup(svc, aws.String(sg_id), duration)

	log.Printf("Finished cleanup for group %s", sg_id)

	return
}

// The main logic that we want to run.  This uses the AWS EC2 API to
// read in the details of the given security group, build a list of
// inbound rules that have expired, then delete those rules.
func cleanSecurityGroup(svc *ec2.EC2, sg_id *string, duration time.Duration) error {
	// create parameter structure for the API call to restrict the
	// result to only the security group that we're interested in
	fetchParams := &ec2.DescribeSecurityGroupsInput{
		GroupIds: []*string{sg_id},
	}
	result, err := svc.DescribeSecurityGroups(fetchParams)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case "InvalidGroupId.Malformed":
				log.Printf("Security Group id %s is malformed: %s.", sg_id, aerr.Message())
			case "InvalidGroup.NotFound":
				log.Printf("Security Group id %s not found: %s.", sg_id, aerr.Message())
			}
		}
		log.Printf("Unable to get description for security group %s, %v", sg_id, err)
		return err
	}

	// Iterate through the inbound rules (the bare `IpPermissions`
	// structure) of the first (and only) security group returned
	deletable := []*ec2.IpPermission{}
	for _, ipPerm := range result.SecurityGroups[0].IpPermissions {
		// SG Rules are aggregated by port/protocol, with potentially multiple CIDR blocks associated as "child" structures
		for _, ipRange := range ipPerm.IpRanges {
			// guard checkExpired() from nil strings; lack of description is considered expired
			if ipRange.Description == nil || checkExpired(*ipRange.Description, duration) {
				if ipRange.Description == nil {
					log.Printf("Will delete rule for %d/%s (no description)", *ipPerm.FromPort, *ipPerm.IpProtocol)
				} else {
					log.Printf("Will delete rule for %d/%s (%s)", *ipPerm.FromPort, *ipPerm.IpProtocol, *ipRange.Description)
				}
				deletable = append(deletable, &ec2.IpPermission{
					FromPort:   ipPerm.FromPort,
					ToPort:     ipPerm.ToPort,
					IpProtocol: ipPerm.IpProtocol,
					IpRanges:   []*ec2.IpRange{ipRange},
				})
			}
		}
	}

	// If there are things to delete, actually do so
	if len(deletable) > 0 {
		revokeInput := &ec2.RevokeSecurityGroupIngressInput{
			GroupId:       sg_id,
			IpPermissions: deletable,
		}
		_, err := svc.RevokeSecurityGroupIngress(revokeInput)
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				case "InvalidPermission.NotFound":
					log.Printf("One or more of the rules targeted for deletion in %s was not found: %s.", sg_id, aerr.Message())
				case "InvalidGroupId.Malformed":
					log.Printf("Security Group id %s is malformed: %s.", sg_id, aerr.Message())
				case "InvalidGroup.NotFound":
					log.Printf("Security Group id %s not found: %s.", sg_id, aerr.Message())
				}
			}
			log.Printf("Something failed revoking security group rules in %s, %v", sg_id, err)
			return err
		}
	}

	return nil
}

// Check the description string from a security group to see if the
// timestamp is expired; also considers invalid-format timestamps are
// also considered expired.  Returns true when expired.
//
// The expected format is simply some text followed by a space then a
// RFC3339-format timestamp.  For example,
//   jcoleman 2019-03-25T19:26:09Z
// would be valid, but just
//   2019-03-25T19:26:09Z
// would not.
func checkExpired(desc string, duration time.Duration) bool {
	if desc == "" {
		return true
	}

	splits := strings.Split(desc, " ")
	desc_ts := splits[len(splits)-1]
	ts, err := time.Parse(time.RFC3339, desc_ts)
	if err != nil {
		// If the last element of the rule description is malformed, just delete the rule anyway
		log.Printf("Malformed time \"%s\" in rule, considering it expired.", desc)
		return true
	}

	return ts.Add(duration).Before(time.Now().UTC())
}
