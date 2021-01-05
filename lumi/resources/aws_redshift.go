package resources

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/redshift"
	"github.com/rs/zerolog/log"
	"go.mondoo.io/mondoo/lumi/library/jobpool"
)

func (r *lumiAwsRedshift) id() (string, error) {
	return "aws.redshift", nil
}

const (
	redshiftClusterArnPattern = "arn:aws:redshift:%s:%s:cluster/%s"
)

func (r *lumiAwsRedshift) GetClusters() ([]interface{}, error) {
	res := []interface{}{}
	poolOfJobs := jobpool.CreatePool(r.getClusters(), 5)
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

func (r *lumiAwsRedshift) getClusters() []*jobpool.Job {
	var tasks = make([]*jobpool.Job, 0)
	at, err := awstransport(r.Runtime.Motor.Transport)
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	account, err := at.Account()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	regions, err := at.GetRegions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		regionVal := region
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("calling aws with region %s", regionVal)

			svc := at.Redshift(regionVal)
			ctx := context.Background()
			res := []interface{}{}

			var marker *string
			for {
				clusters, err := svc.DescribeClustersRequest(&redshift.DescribeClustersInput{Marker: marker}).Send(ctx)
				if err != nil {
					return nil, err
				}
				for _, cluster := range clusters.Clusters {
					var names []interface{}
					for _, group := range cluster.ClusterParameterGroups {
						names = append(names, toString(group.ParameterGroupName))
					}
					lumiDBInstance, err := r.Runtime.CreateResource("aws.redshift.cluster",
						"arn", fmt.Sprintf(redshiftClusterArnPattern, regionVal, account.ID, toString(cluster.ClusterIdentifier)),
						"name", toString(cluster.ClusterIdentifier),
						"region", regionVal,
						"encrypted", toBool(cluster.Encrypted),
						"nodeType", toString(cluster.NodeType),
						"allowVersionUpgrade", toBool(cluster.AllowVersionUpgrade),
						"preferredMaintenanceWindow", toString(cluster.PreferredMaintenanceWindow),
						"automatedSnapshotRetentionPeriod", toInt64(cluster.AutomatedSnapshotRetentionPeriod),
						"publiclyAccessible", toBool(cluster.PubliclyAccessible),
						"clusterParameterGroupNames", names,
					)
					if err != nil {
						return nil, err
					}
					res = append(res, lumiDBInstance)
				}
				if clusters.Marker == nil {
					break
				}
				marker = clusters.Marker
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (r *lumiAwsRedshiftCluster) id() (string, error) {
	return r.Arn()
}

func (r *lumiAwsRedshiftCluster) GetParameters() ([]interface{}, error) {
	clusterGroupNames, err := r.ClusterParameterGroupNames()
	if err != nil {
		return nil, err
	}
	region, err := r.Region()
	if err != nil {
		return nil, err
	}
	at, err := awstransport(r.Runtime.Motor.Transport)
	if err != nil {
		return nil, err
	}

	svc := at.Redshift(region)
	ctx := context.Background()
	res := []redshift.Parameter{}
	for _, name := range clusterGroupNames {
		stringName := name.(string)
		params, err := svc.DescribeClusterParametersRequest(&redshift.DescribeClusterParametersInput{ParameterGroupName: &stringName}).Send(ctx)
		if err != nil {
			return nil, err
		}
		res = append(res, params.Parameters...)
	}
	return jsonToDictSlice(res)
}

func (r *lumiAwsRedshiftCluster) GetLogging() (interface{}, error) {
	name, err := r.Name()
	if err != nil {
		return nil, err
	}
	region, err := r.Region()
	if err != nil {
		return nil, err
	}
	at, err := awstransport(r.Runtime.Motor.Transport)
	if err != nil {
		return nil, err
	}

	svc := at.Redshift(region)
	ctx := context.Background()

	params, err := svc.DescribeLoggingStatusRequest(&redshift.DescribeLoggingStatusInput{ClusterIdentifier: &name}).Send(ctx)
	if err != nil {
		return nil, err
	}
	return jsonToDict(params)
}