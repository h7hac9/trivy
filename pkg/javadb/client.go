package javadb

import (
	"golang.org/x/xerrors"
	"sort"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/java/jar"
	"github.com/h7hac9/trivy-java-db/pkg/db"
	"github.com/h7hac9/trivy-java-db/pkg/types"
)

var config *types.DBConfig

func Init(dbAuthURL string) {
	config = &types.DBConfig{MysqlDBConfig: &types.MysqlDBConfig{DBConnectURL: dbAuthURL}}
}

type DB struct {
	driver db.DB
}

func NewClient() (*DB, error) {
	dbc, err := db.New("", config)
	if err != nil {
		return nil, xerrors.Errorf("Java DB open error: %w", err)
	}

	return &DB{driver: dbc}, nil
}

func (d *DB) Exists(groupID, artifactID string) (bool, error) {
	index, err := d.driver.SelectIndexByArtifactIDAndGroupID(artifactID, groupID)
	if err != nil {
		return false, err
	}
	return index.ArtifactID != "", nil
}

func (d *DB) SearchBySHA1(sha1 string) (jar.Properties, error) {
	index, err := d.driver.SelectIndexBySha1(sha1)
	if err != nil {
		return jar.Properties{}, xerrors.Errorf("select error: %w", err)
	} else if index.ArtifactID == "" {
		return jar.Properties{}, xerrors.Errorf("digest %s: %w", sha1, jar.ArtifactNotFoundErr)
	}
	return jar.Properties{
		GroupID:    index.GroupID,
		ArtifactID: index.ArtifactID,
		Version:    index.Version,
	}, nil
}

func (d *DB) SearchByArtifactID(artifactID, version string) (string, error) {
	indexes, err := d.driver.SelectIndexesByArtifactIDAndFileType(artifactID, version, types.JarType)
	if err != nil {
		return "", xerrors.Errorf("select error: %w", err)
	} else if len(indexes) == 0 {
		return "", xerrors.Errorf("artifactID %s: %w", artifactID, jar.ArtifactNotFoundErr)
	}
	sort.Slice(indexes, func(i, j int) bool {
		return indexes[i].GroupID < indexes[j].GroupID
	})

	// Some artifacts might have the same artifactId.
	// e.g. "javax.servlet:jstl" and "jstl:jstl"
	groupIDs := make(map[string]int)
	for _, index := range indexes {
		if i, ok := groupIDs[index.GroupID]; ok {
			groupIDs[index.GroupID] = i + 1
			continue
		}
		groupIDs[index.GroupID] = 1
	}
	maxCount := 0
	var groupID string
	for k, v := range groupIDs {
		if v > maxCount {
			maxCount = v
			groupID = k
		}
	}

	return groupID, nil
}

func (d *DB) Close() error {
	if d == nil {
		return nil
	}
	return d.driver.Close()
}
