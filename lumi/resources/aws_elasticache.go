package resources

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/rs/zerolog/log"
	"go.mondoo.io/mondoo/lumi/library/jobpool"
)

func (e *lumiAwsElasticache) id() (string, error) {
	return "aws.elasticache", nil
}

func (e *lumiAwsElasticache) GetClusters() ([]interface{}, error) {
	res := []interface{}{}
	poolOfJobs := jobpool.CreatePool(e.getClusters(), 5)
	poolOfJobs.Run()

	// check for errors
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	// get all the results
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]interface{})...)
		}
	}

	return res, nil
}

func (e *lumiAwsElasticache) getClusters() []*jobpool.Job {
	var tasks = make([]*jobpool.Job, 0)
	at, err := awstransport(e.Runtime.Motor.Transport)
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

			svc := at.Elasticache(regionVal)
			ctx := context.Background()
			res := []elasticache.CacheCluster{}

			var marker *string
			for {
				clusters, err := svc.DescribeCacheClustersRequest(&elasticache.DescribeCacheClustersInput{Marker: marker}).Send(ctx)
				if err != nil {
					return nil, err
				}
				if len(clusters.CacheClusters) == 0 {
					return nil, nil
				}
				res = append(res, clusters.CacheClusters...)
				if clusters.Marker == nil {
					break
				}
				marker = clusters.Marker
			}
			jsonRes, err := jsonToDictSlice(res)
			if err != nil {
				return nil, err
			}
			return jobpool.JobResult(jsonRes), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}