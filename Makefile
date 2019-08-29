
DATE := $(shell /bin/date "+%Y-%m-%d-%H-%M-%S")
GOPATH := ${PWD}/gopath
STACKNAME := demo-bastion-security

AWS_REGION := ca-central-1
AWS_PROFILE := default

all: LambdaHandler bastion-util

distclean: clean
	rm -rf gopath *~

clean:
	rm -f LambdaHandler LambdaHandler*.zip bastion-util stack-outputs.json

gopath:
	mkdir ${GOPATH}
	go get -d

%:%.go gopath
	go build -o $@ $<

deploy: stack-outputs.json
	rm -f LambdaHandler
	GOOS=linux go build -o LambdaHandler LambdaHandler.go
	zip LambdaHandler-${DATE}.zip LambdaHandler
	$(eval BUCKET := $(shell jq -r '.[] | select(.OutputKey == "s3Bucket") | .OutputValue' stack-outputs.json ))
	aws s3 cp LambdaHandler-${DATE}.zip "s3://${BUCKET}/LambdaHandler-${DATE}.zip"
	echo "Pushed lambda handler to s3://${BUCKET}/LambdaHandler-${DATE}.zip"

stack-outputs.json:
	aws --region ${AWS_REGION} --profile ${AWS_PROFILE} cloudformation describe-stacks --stack-name ${STACKNAME} --query 'Stacks[0].Outputs' > stack-outputs.json

create-stack:
	aws --region ${AWS_REGION} --profile ${AWS_PROFILE} cloudformation create-stack --stack-name ${STACKNAME} --template-body file://demo-bastion-security.yaml --capabilities CAPABILITY_IAM

update-stack:
	aws --region ${AWS_REGION} --profile ${AWS_PROFILE} cloudformation update-stack --stack-name ${STACKNAME} --template-body file://demo-bastion-security.yaml --capabilities CAPABILITY_IAM
