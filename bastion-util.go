// (C) Copyright 2019 Kira Systems
//
// This file contains the necessary code for a commandline utility
// that can insert security group rules into AWS, allow access on
// port 22/TCP (the ports typically used by SSH).
//
//

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/iam"
)

const (
	ip_api_url = "https://checkip.amazonaws.com" // URL that returns that caller's raw IP address as a string
	version    = "1.0"
)

var verbose = flag.Bool("v", false, "Verbose logging to stdout")

var remove_only = flag.Bool("remove-only", false, "Only remove rules that match the IP address and/or user, do not create new rules.")
var display_only = flag.Bool("display-only", false, "Only print the rules that are in the target security group.")

var profile = flag.String("profile", "default", "AWS Credentials profile")
var region = flag.String("region", "ca-central-1", "Target AWS Region")

var user = flag.String("user", "", "Username to use when adding/removing rules")
var cidr = flag.String("cidr", "", "CIDR block to use when adding/removing rules")

var target_sg_id = flag.String("target-sg-id", "", "Target Security Group")
var target_tag_name = flag.String("target-tag-name", "Name", "The name of tag to filter on if searching for the security group")
var target_tag_query = flag.String("target-tag-query", "*Dynamic Bastion SG", "")

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "%s version %s\nUsage:\n", os.Args[0], version)
		flag.PrintDefaults()
	}
	flag.Parse()

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})
	if *verbose {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	}

	// Set up the AWS Session object
	sess := session.Must(session.NewSession(&aws.Config{
		Region:      region,
		Credentials: credentials.NewSharedCredentials("", *profile),
	}))

	// Fetch the username associated with the created session
	if user == nil || *user == "" {
		user = getUser(sess)
		log.Info().Msgf("Associated AWS user is %s.", *user)
	} else {
		log.Info().Msgf("Username is %s.", *user)
	}

	// Set up a service object for the EC2 API
	ec2_svc := ec2.New(sess)

	// Figure out the local public IP address, either via a 3rd-party service, or via cmdline param
	if cidr == nil || *cidr == "" {
		cidr = getCidr()
	}
	log.Info().Msgf("Using %s as the public CIDR.", *cidr)

	// Fetch the which Security Group we're going to use/modify
	var target_group *ec2.SecurityGroup
	if target_sg_id == nil || *target_sg_id == "" {
		target_group = fetchGroupByQuery(ec2_svc, target_tag_name, target_tag_query)
	} else {
		target_group = fetchGroupById(ec2_svc, target_sg_id)
	}

	if *display_only {
		printRules(target_group)
	} else {
		deleteRules(ec2_svc, target_group, cidr, user)
		if !*remove_only {
			createRules(ec2_svc, target_group.GroupId, user, cidr)
		}
	}
}

func getCidr() *string {
	resp, err := http.Get(ip_api_url)
	if err != nil {
		log.Fatal().Msgf("Fetch of IP address from %s failed: %v\n", ip_api_url, err)
	}

	buf, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatal().Msgf("Fetch of IP address from %s failed reading response: %v\n", ip_api_url, err)
		os.Exit(1)
	}

	cidr := fmt.Sprintf("%s/32", strings.TrimSpace(string(buf)))
	return &cidr
}

func fetchGroupByQuery(svc *ec2.EC2, tag_name *string, tag_query *string) *ec2.SecurityGroup {
	filter_name := fmt.Sprintf("tag:%s", *tag_name)
	input := &ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{
			{
				Name:   &filter_name,
				Values: []*string{tag_query},
			},
		},
	}

	groups, err := svc.DescribeSecurityGroups(input)
	if err != nil {
		log.Fatal().Msgf("Error fetching security group: %v", err)
	}
	if len(groups.SecurityGroups) != 1 {
		log.Fatal().Msgf("Found %d (not 1) security groups matching tag name \"%s\", query \"%s\"", len(groups.SecurityGroups), *tag_name, *tag_query)
	}

	return groups.SecurityGroups[0]
}

func fetchGroupById(svc *ec2.EC2, sg_id *string) *ec2.SecurityGroup {
	groups, err := svc.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
		GroupIds: []*string{sg_id},
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case "InvalidGroupId.Malformed":
				log.Fatal().Msgf("Malformed security group id %s: %v", *sg_id, err)
			case "InvalidGroup.NotFound":
				log.Fatal().Msgf("Security group id %s not found: %v", *sg_id, err)
			}
		}
		log.Fatal().Msgf("Unable to get descriptions for security group %s, %v", *sg_id, err)
	}

	return groups.SecurityGroups[0]
}

func deleteRules(svc *ec2.EC2, group *ec2.SecurityGroup, cidr *string, user *string) {
	deletable := []*ec2.IpPermission{}

	for _, ipPerm := range group.IpPermissions {
		for _, ipRange := range ipPerm.IpRanges {
			if *cidr == *ipRange.CidrIp { // delete rules that match the target CIDR
				if ipRange.Description == nil {
					log.Debug().Msgf("Found CIDR match: %s:%d/%s (<no description>)", *ipRange.CidrIp, *ipPerm.FromPort, *ipPerm.IpProtocol)
				} else {
					log.Debug().Msgf("Found CIDR match: %s:%d/%s (%s)", *ipRange.CidrIp, *ipPerm.FromPort, *ipPerm.IpProtocol, *ipRange.Description)
				}
				deletable = append(deletable, &ec2.IpPermission{
					FromPort:   ipPerm.FromPort,
					ToPort:     ipPerm.ToPort,
					IpProtocol: ipPerm.IpProtocol,
					IpRanges:   []*ec2.IpRange{ipRange},
				})
			} else if ipRange.Description != nil && strings.HasPrefix(*ipRange.Description, *user) { // delete rules that match the target user
				log.Debug().Msgf("Found user match: %s:%d/%s (%s)", *ipRange.CidrIp, *ipPerm.FromPort, *ipPerm.IpProtocol, *ipRange.Description)
				deletable = append(deletable, &ec2.IpPermission{
					FromPort:   ipPerm.FromPort,
					ToPort:     ipPerm.ToPort,
					IpProtocol: ipPerm.IpProtocol,
					IpRanges:   []*ec2.IpRange{ipRange},
				})
			}
		}
	}

	if len(deletable) > 0 {
		log.Info().Msgf("Will remove %d rules...", len(deletable))
		revokeInput := &ec2.RevokeSecurityGroupIngressInput{
			GroupId:       group.GroupId,
			IpPermissions: deletable,
		}
		_, err := svc.RevokeSecurityGroupIngress(revokeInput)
		if err != nil {
			log.Fatal().Msgf("Unable to delete rules in security group %s: %v", *group.GroupId, err)
		}
		log.Info().Msg("...done deleting old rules.")
	} else {
		log.Info().Msg("No rules found to delete.")
	}
}

func createRules(svc *ec2.EC2, sg_id *string, user *string, cidr *string) {
	description := fmt.Sprintf("%s %s", *user, time.Now().UTC().Format(time.RFC3339))
	auth_params := &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: sg_id,
		IpPermissions: []*ec2.IpPermission{
			{
				FromPort:   aws.Int64(22),
				ToPort:     aws.Int64(22),
				IpProtocol: aws.String("tcp"),
				IpRanges: []*ec2.IpRange{
					{
						CidrIp:      cidr,
						Description: &description,
					},
				},
			},
		},
	}

	log.Info().Msgf("Creating new rules in %s with descrption \"%s\"...", *sg_id, description)

	_, err := svc.AuthorizeSecurityGroupIngress(auth_params)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case "InvalidGroupId.Malformed":
				log.Fatal().Msgf("Malformed security group id %s: %v", *sg_id, err)
			case "InvalidGroup.NotFound":
				log.Fatal().Msgf("Security group id %s not found: %v", *sg_id, err)
			case "InvalidPermission.Duplicate":
				log.Fatal().Msgf("At least one of the new rules for %s was a duplicate: %v", *sg_id, err)
			case "InvalidPermission.Malformed":
				log.Fatal().Msgf("At least one of the new rules for %s was malformed: %v", *sg_id, err)
			case "RulesPerSecurityGroupLimitExceeded":
				log.Fatal().Msgf("There are far too many rules in security group %s (exceeded AWS' rules-per-group limit): %v", *sg_id, err)
			}
		}
		log.Fatal().Msgf("Something went wrong creating the new rules: %v", err)
	}
	log.Info().Msg("...done creating new rules.")
}

func printRules(group *ec2.SecurityGroup) {
	fmt.Printf("Security Group %s — %s\n", *group.GroupId, *group.GroupName)
	if len(group.IpPermissions) == 0 {
		fmt.Printf("  No rules present\n")
	}
	for _, ipPerm := range group.IpPermissions {
		fmt.Printf("  IpPermission: %d/%s\n", *ipPerm.FromPort, *ipPerm.IpProtocol)
		for _, ipRange := range ipPerm.IpRanges {
			if ipRange.Description != nil {
				fmt.Printf("    %s — %s\n", *ipRange.CidrIp, *ipRange.Description)
			} else {
				fmt.Printf("    %s\n", *ipRange.CidrIp)
			}
		}
	}
}

func getUser(sess *session.Session) *string {
	user_result, err := iam.New(sess).GetUser(nil)
	if err != nil {
		log.Fatal().Msgf("Unable to fetch the username associated with the current API session: %v", err)
	}

	return user_result.User.UserName
}
