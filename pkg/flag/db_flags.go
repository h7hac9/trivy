package flag

import (
	"fmt"

	"github.com/google/go-containerregistry/pkg/name"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
)

var (
	// Deprecated
	ResetFlag = Flag[bool]{
		Name:       "reset",
		ConfigName: "reset",
		Usage:      "remove all caches and database",
		Removed:    `Use "trivy clean --all" instead.`,
	}
	DownloadDBOnlyFlag = Flag[bool]{
		Name:       "download-db-only",
		ConfigName: "db.download-only",
		Usage:      "download/update vulnerability database but don't run a scan",
	}
	SkipDBUpdateFlag = Flag[bool]{
		Name:       "skip-db-update",
		ConfigName: "db.skip-update",
		Usage:      "skip updating vulnerability database",
		Aliases: []Alias{
			{
				Name:       "skip-update",
				Deprecated: true, // --skip-update was renamed to --skip-db-update
			},
		},
	}
	DownloadJavaDBOnlyFlag = Flag[bool]{
		Name:       "download-java-db-only",
		ConfigName: "db.download-java-only",
		Usage:      "download/update Java index database but don't run a scan",
	}
	SkipJavaDBUpdateFlag = Flag[bool]{
		Name:       "skip-java-db-update",
		ConfigName: "db.java-skip-update",
		Usage:      "skip updating Java index database",
	}
	NoProgressFlag = Flag[bool]{
		Name:       "no-progress",
		ConfigName: "db.no-progress",
		Usage:      "suppress progress bar",
	}
	DBRepositoryFlag = Flag[string]{
		Name:       "db-repository",
		ConfigName: "db.repository",
		Default:    db.DefaultRepository,
		Usage:      "OCI repository to retrieve trivy-db from",
	}
	JavaDBAuthURLFlag = Flag[string]{
		Name:       "java-db-auth-url",
		ConfigName: "db.java-db-auth-url",
		Default:    "",
		Usage:      "Java DB auth URL",
	}
	LightFlag = Flag[bool]{
		Name:       "light",
		ConfigName: "db.light",
		Usage:      "deprecated",
		Deprecated: `This flag is ignored.`,
	}
)

// DBFlagGroup composes common printer flag structs used for commands requiring DB logic.
type DBFlagGroup struct {
	Reset              *Flag[bool]
	DownloadDBOnly     *Flag[bool]
	SkipDBUpdate       *Flag[bool]
	DownloadJavaDBOnly *Flag[bool]
	SkipJavaDBUpdate   *Flag[bool]
	NoProgress         *Flag[bool]
	DBRepository       *Flag[string]
	JavaDBAuthURLFlag  *Flag[string]
	Light              *Flag[bool] // deprecated
}

type DBOptions struct {
	Reset              bool
	DownloadDBOnly     bool
	SkipDBUpdate       bool
	DownloadJavaDBOnly bool
	SkipJavaDBUpdate   bool
	NoProgress         bool
	DBRepository       name.Reference
	JavaDBRepository   name.Reference
	JavaDBAuthURL      string
}

// NewDBFlagGroup returns a default DBFlagGroup
func NewDBFlagGroup() *DBFlagGroup {
	return &DBFlagGroup{
		Reset:              ResetFlag.Clone(),
		DownloadDBOnly:     DownloadDBOnlyFlag.Clone(),
		SkipDBUpdate:       SkipDBUpdateFlag.Clone(),
		DownloadJavaDBOnly: DownloadJavaDBOnlyFlag.Clone(),
		SkipJavaDBUpdate:   SkipJavaDBUpdateFlag.Clone(),
		Light:              LightFlag.Clone(),
		NoProgress:         NoProgressFlag.Clone(),
		DBRepository:       DBRepositoryFlag.Clone(),
		JavaDBAuthURLFlag:  JavaDBAuthURLFlag.Clone(),
	}
}

func (f *DBFlagGroup) Name() string {
	return "DB"
}

func (f *DBFlagGroup) Flags() []Flagger {
	return []Flagger{
		f.Reset,
		f.DownloadDBOnly,
		f.SkipDBUpdate,
		f.DownloadJavaDBOnly,
		f.SkipJavaDBUpdate,
		f.NoProgress,
		f.DBRepository,
		f.JavaDBAuthURLFlag,
		f.Light,
	}
}

func (f *DBFlagGroup) ToOptions() (DBOptions, error) {
	if err := parseFlags(f); err != nil {
		return DBOptions{}, err
	}

	skipDBUpdate := f.SkipDBUpdate.Value()
	skipJavaDBUpdate := f.SkipJavaDBUpdate.Value()
	downloadDBOnly := f.DownloadDBOnly.Value()
	downloadJavaDBOnly := f.DownloadJavaDBOnly.Value()
	javaDBAuthURL := f.JavaDBAuthURLFlag.Value()

	if downloadDBOnly && skipDBUpdate {
		return DBOptions{}, xerrors.New("--skip-db-update and --download-db-only options can not be specified both")
	}
	if downloadJavaDBOnly && skipJavaDBUpdate {
		return DBOptions{}, xerrors.New("--skip-java-db-update and --download-java-db-only options can not be specified both")
	}

	var dbRepository, javaDBRepository name.Reference
	var err error
	if f.DBRepository != nil {
		if dbRepository, err = name.ParseReference(f.DBRepository.Value(), name.WithDefaultTag("")); err != nil {
			return DBOptions{}, xerrors.Errorf("invalid db repository: %w", err)
		}
		// Add the schema version if the tag is not specified for backward compatibility.
		if t, ok := dbRepository.(name.Tag); ok && t.TagStr() == "" {
			dbRepository = t.Tag(fmt.Sprint(db.SchemaVersion))
			log.Info("Adding schema version to the DB repository for backward compatibility",
				log.String("repository", dbRepository.String()))
		}
	}

	return DBOptions{
		Reset:              f.Reset.Value(),
		DownloadDBOnly:     downloadDBOnly,
		SkipDBUpdate:       skipDBUpdate,
		DownloadJavaDBOnly: downloadJavaDBOnly,
		SkipJavaDBUpdate:   skipJavaDBUpdate,
		NoProgress:         f.NoProgress.Value(),
		DBRepository:       dbRepository,
		JavaDBRepository:   javaDBRepository,
		JavaDBAuthURL:      javaDBAuthURL,
	}, nil
}
