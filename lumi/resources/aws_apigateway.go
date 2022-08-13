package resources

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.io/mondoo/lumi/library/jobpool"
	aws_transport "go.mondoo.io/mondoo/motor/providers/aws"
)

func (a *lumiAwsApigateway) id() (string, error) {
	return "aws.apigateway", nil
}

const (
	apiArnPattern      = "arn:aws:apigateway:%s:%s::/apis/%s"
	apiStageArnPattern = "arn:aws:apigateway:%s:%s::/apis/%s/stages/%s"
)

func (a *lumiAwsApigateway) GetRestApis() ([]interface{}, error) {
	at, err := awstransport(a.MotorRuntime.Motor.Transport)
	if err != nil {
		return nil, err
	}
	res := []interface{}{}
	poolOfJobs := jobpool.CreatePool(a.getRestApis(at), 5)
	poolOfJobs.Run()

	// check for errors
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	// get all the results
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]interface{})...)
	}

	return res, nil
}

func (a *lumiAwsApigateway) getRestApis(at *aws_transport.Provider) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := at.GetRegions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	account, err := at.Account()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		regionVal := region
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("calling aws with region %s", regionVal)

			svc := at.Apigateway(regionVal)
			ctx := context.Background()

			res := []interface{}{}
			var position *string
			for {
				restApisResp, err := svc.GetRestApis(ctx, &apigateway.GetRestApisInput{Position: position})
				if err != nil {
					return nil, errors.Wrap(err, "could not gather aws apigateway rest apis")
				}

				for _, restApi := range restApisResp.Items {
					lumiRestApi, err := a.MotorRuntime.CreateResource("aws.apigateway.restapi",
						"arn", fmt.Sprintf(apiArnPattern, regionVal, account.ID, toString(restApi.Id)),
						"id", toString(restApi.Id),
						"name", toString(restApi.Name),
						"description", toString(restApi.Description),
						"createdDate", restApi.CreatedDate,
						"region", regionVal,
						"tags", mapTagsToLumiMapTags(restApi.Tags),
					)
					if err != nil {
						return nil, err
					}
					res = append(res, lumiRestApi)
				}
				if restApisResp.Position == nil {
					break
				}
				position = restApisResp.Position
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *lumiAwsApigatewayRestapi) GetStages() ([]interface{}, error) {
	restApiId, err := a.Id()
	if err != nil {
		return nil, err
	}
	region, err := a.Region()
	if err != nil {
		return nil, err
	}
	at, err := awstransport(a.MotorRuntime.Motor.Transport)
	if err != nil {
		return nil, err
	}
	account, err := at.Account()
	if err != nil {
		return nil, err
	}
	svc := at.Apigateway(region)
	ctx := context.Background()

	// no pagination required
	stagesResp, err := svc.GetStages(ctx, &apigateway.GetStagesInput{RestApiId: &restApiId})
	if err != nil {
		return nil, errors.Wrap(err, "could not gather aws api gateway stages")
	}
	res := []interface{}{}
	for _, stage := range stagesResp.Item {
		dictMethodSettings, err := jsonToDict(stage.MethodSettings)
		if err != nil {
			return nil, err
		}
		lumiStage, err := a.MotorRuntime.CreateResource("aws.apigateway.stage",
			"arn", fmt.Sprintf(apiStageArnPattern, region, account.ID, restApiId, toString(stage.StageName)),
			"name", toString(stage.StageName),
			"description", toString(stage.Description),
			"tracingEnabled", stage.TracingEnabled,
			"deploymentId", toString(stage.DeploymentId),
			"methodSettings", dictMethodSettings,
		)
		if err != nil {
			return nil, err
		}
		res = append(res, lumiStage)
	}
	return res, nil
}

func (l *lumiAwsApigatewayRestapi) id() (string, error) {
	return l.Arn()
}

func (l *lumiAwsApigatewayStage) id() (string, error) {
	return l.Arn()
}
