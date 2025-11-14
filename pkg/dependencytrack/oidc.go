package dependencytrack

import (
	"context"
	"fmt"
	"net/http"

	"github.com/KvalitetsIT/dtrack/pkg/dependencytrack/client"
	log "github.com/sirupsen/logrus"
)

type OidcGroup struct {
	Uuid string `json:"uuid,omitempty"`
	Name string `json:"name,omitempty"`
}

func (c *managementClient) CreateOidcGroup(ctx context.Context, groupName string) (*OidcGroup, error) {
	return withAuthContextValue(c.auth, ctx, func(tokenCtx context.Context) (*OidcGroup, error) {
		group, resp, err := c.client.OidcAPI.CreateGroup(tokenCtx).
			OidcGroup(client.OidcGroup{
				Uuid: "",
				Name: groupName,
			}).Execute()
		if err != nil {
			return nil, convertError(err, "CreateOidcGroup", resp)
		}

		log.Infof("created OIDC group %s with UUID %s", group.Name, group.Uuid)
		return &OidcGroup{
			Uuid: group.Uuid,
			Name: group.Name,
		}, nil
	})
}

func (c *managementClient) GetOidcGroups(ctx context.Context) ([]*OidcGroup, error) {
	return withAuthContextValue(c.auth, ctx, func(tokenCtx context.Context) ([]*OidcGroup, error) {
		groups, resp, err := c.client.OidcAPI.RetrieveGroups(tokenCtx).Execute()
		if err != nil {
			return nil, convertError(err, "GetOidcGroups", resp)
		}

		result := make([]*OidcGroup, 0, len(groups))
		for _, g := range groups {
			result = append(result, &OidcGroup{
				Uuid: g.Uuid,
				Name: g.Name,
			})
		}
		return result, nil
	})
}

func (c *managementClient) GetOidcGroup(ctx context.Context, groupName string) (*OidcGroup, error) {
	return withAuthContextValue(c.auth, ctx, func(tokenCtx context.Context) (*OidcGroup, error) {
		groups, resp, err := c.client.OidcAPI.RetrieveGroups(tokenCtx).Execute()
		if err != nil {
			return nil, convertError(err, "GetOidcGroup", resp)
		}

		for _, g := range groups {
			if g.Name == groupName {
				return &OidcGroup{
					Uuid: g.Uuid,
					Name: g.Name,
				}, nil
			}
		}
		return nil, fmt.Errorf("OIDC group %s not found", groupName)
	})
}

func (c *managementClient) MapOidcGroupToTeam(ctx context.Context, groupUuid, teamUuid string) error {
	return c.withAuthContext(ctx, func(tokenCtx context.Context) error {
		_, resp, err := c.client.OidcAPI.AddMapping2(tokenCtx).
			MappedOidcGroupRequest(client.MappedOidcGroupRequest{
				Group: groupUuid,
				Team:  teamUuid,
			}).Execute()
		if err != nil {
			switch resp.StatusCode {
			case http.StatusNotModified:
				log.Infof("OIDC group %s is already mapped to team %s", groupUuid, teamUuid)
				return nil
			default:
				return convertError(err, "MapOidcGroupToTeam", resp)
			}
		}
		return nil
	})
}

func (c *managementClient) DeleteOidcGroup(ctx context.Context, uuid string) error {
	return c.withAuthContext(ctx, func(tokenCtx context.Context) error {
		resp, err := c.client.OidcAPI.DeleteGroup(tokenCtx, uuid).Execute()
		if err != nil {
			if resp.StatusCode == http.StatusNotFound {
				log.Infof("OIDC group %s does not exist", uuid)
				return nil
			}
			return convertError(err, "DeleteOidcGroup", resp)
		}
		return nil
	})
}
