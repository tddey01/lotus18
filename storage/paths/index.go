package paths

import (
	"context"
	"errors"
	"net/url"
	gopath "path"
	"sync"
	"time"
	//yungojs
	"github.com/filecoin-project/go-state-types/big"
	"github.com/google/uuid"
	"sort"

	"go.opencensus.io/stats"
	"go.opencensus.io/tag"
	"golang.org/x/xerrors"

	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/lotus/journal/alerting"
	"github.com/filecoin-project/lotus/metrics"
	"github.com/filecoin-project/lotus/storage/sealer/fsutil"
	"github.com/filecoin-project/lotus/storage/sealer/storiface"
)

var HeartbeatInterval = 10 * time.Second
var SkippedHeartbeatThresh = HeartbeatInterval * 5
var storageTime = time.Minute * 5 //yungojs

//go:generate go run github.com/golang/mock/mockgen -destination=mocks/index.go -package=mocks . SectorIndex

type SectorIndex interface { // part of storage-miner api
	//yungojs
	StorageSetWeight(ctx context.Context, storageID storiface.ID) error
	StorageLockByID(ctx context.Context, storageID storiface.ID, uid uuid.UUID) (int, error)
	StorageUnLockByID(ctx context.Context, storageID storiface.ID, uid uuid.UUID) error

	StorageAttach(context.Context, storiface.StorageInfo, fsutil.FsStat) error
	StorageDetach(ctx context.Context, id storiface.ID, url string) error
	StorageInfo(context.Context, storiface.ID) (storiface.StorageInfo, error)
	StorageReportHealth(context.Context, storiface.ID, storiface.HealthReport) error

	StorageDeclareSector(ctx context.Context, storageID storiface.ID, s abi.SectorID, ft storiface.SectorFileType, primary bool) error
	StorageDropSector(ctx context.Context, storageID storiface.ID, s abi.SectorID, ft storiface.SectorFileType) error
	StorageFindSector(ctx context.Context, sector abi.SectorID, ft storiface.SectorFileType, ssize abi.SectorSize, allowFetch bool) ([]storiface.SectorStorageInfo, error)

	StorageBestAlloc(ctx context.Context, allocate storiface.SectorFileType, ssize abi.SectorSize, pathType storiface.PathType) ([]storiface.StorageInfo, error)

	// atomically acquire locks on all sector file types. close ctx to unlock
	StorageLock(ctx context.Context, sector abi.SectorID, read storiface.SectorFileType, write storiface.SectorFileType) error
	StorageTryLock(ctx context.Context, sector abi.SectorID, read storiface.SectorFileType, write storiface.SectorFileType) (bool, error)
	StorageGetLocks(ctx context.Context) (storiface.SectorLocks, error)

	StorageList(ctx context.Context) (map[storiface.ID][]storiface.Decl, error)
}

type declMeta struct {
	storage storiface.ID
	primary bool
}

type storageEntry struct {
	info *storiface.StorageInfo
	fsi  fsutil.FsStat

	lastHeartbeat time.Time
	heartbeatErr  error

	rw []storageQueue //yungojs
}

//yungojs
type storageQueue struct {
	uid         uuid.UUID
	requestTime time.Time
}

type Index struct {
	*indexLocks
	lk sync.RWMutex

	// optional
	alerting   *alerting.Alerting
	pathAlerts map[storiface.ID]alerting.AlertType

	sectors map[storiface.Decl][]*declMeta
	stores  map[storiface.ID]*storageEntry
}

func NewIndex(al *alerting.Alerting) *Index {
	return &Index{
		indexLocks: &indexLocks{
			locks: map[abi.SectorID]*sectorLock{},
		},

		alerting:   al,
		pathAlerts: map[storiface.ID]alerting.AlertType{},

		sectors: map[storiface.Decl][]*declMeta{},
		stores:  map[storiface.ID]*storageEntry{},
	}
}

func (i *Index) StorageList(ctx context.Context) (map[storiface.ID][]storiface.Decl, error) {
	i.lk.RLock()
	defer i.lk.RUnlock()

	byID := map[storiface.ID]map[abi.SectorID]storiface.SectorFileType{}

	for id := range i.stores {
		byID[id] = map[abi.SectorID]storiface.SectorFileType{}
	}
	for decl, ids := range i.sectors {
		for _, id := range ids {
			byID[id.storage][decl.SectorID] |= decl.SectorFileType
		}
	}

	out := map[storiface.ID][]storiface.Decl{}
	for id, m := range byID {
		out[id] = []storiface.Decl{}
		for sectorID, fileType := range m {
			out[id] = append(out[id], storiface.Decl{
				SectorID:       sectorID,
				SectorFileType: fileType,
			})
		}
	}

	return out, nil
}

func (i *Index) StorageAttach(ctx context.Context, si storiface.StorageInfo, st fsutil.FsStat) error {
	var allow, deny = make([]string, 0, len(si.AllowTypes)), make([]string, 0, len(si.DenyTypes))

	if _, hasAlert := i.pathAlerts[si.ID]; i.alerting != nil && !hasAlert {
		i.pathAlerts[si.ID] = i.alerting.AddAlertType("sector-index", "pathconf-"+string(si.ID))
	}

	var hasConfigIssues bool

	for id, typ := range si.AllowTypes {
		_, err := storiface.TypeFromString(typ)
		if err != nil {
			// No need to hard-fail here, just warn the user
			// (note that even with all-invalid entries we'll deny all types, so nothing unexpected should enter the path)
			hasConfigIssues = true

			if i.alerting != nil {
				i.alerting.Raise(i.pathAlerts[si.ID], map[string]interface{}{
					"message":   "bad path type in AllowTypes",
					"path":      string(si.ID),
					"idx":       id,
					"path_type": typ,
					"error":     err.Error(),
				})
			}

			continue
		}
		allow = append(allow, typ)
	}
	for id, typ := range si.DenyTypes {
		_, err := storiface.TypeFromString(typ)
		if err != nil {
			// No need to hard-fail here, just warn the user
			hasConfigIssues = true

			if i.alerting != nil {
				i.alerting.Raise(i.pathAlerts[si.ID], map[string]interface{}{
					"message":   "bad path type in DenyTypes",
					"path":      string(si.ID),
					"idx":       id,
					"path_type": typ,
					"error":     err.Error(),
				})
			}

			continue
		}
		deny = append(deny, typ)
	}
	si.AllowTypes = allow
	si.DenyTypes = deny

	if i.alerting != nil && !hasConfigIssues && i.alerting.IsRaised(i.pathAlerts[si.ID]) {
		i.alerting.Resolve(i.pathAlerts[si.ID], map[string]string{
			"message": "path config is now correct",
		})
	}

	i.lk.Lock()
	defer i.lk.Unlock()

	//log.Infof("New sector storage: %s", si.ID)	//yungojs

	if _, ok := i.stores[si.ID]; ok {
		for _, u := range si.URLs {
			if _, err := url.Parse(u); err != nil {
				return xerrors.Errorf("failed to parse url %s: %w", si.URLs, err)
			}
		}

	uloop:
		for _, u := range si.URLs {
			for _, l := range i.stores[si.ID].info.URLs {
				if u == l {
					continue uloop
				}
			}

			i.stores[si.ID].info.URLs = append(i.stores[si.ID].info.URLs, u)
		}
		i.stores[si.ID].info.LocalPath = si.LocalPath //yungojs

		i.stores[si.ID].info.Weight = si.Weight
		i.stores[si.ID].info.MaxStorage = si.MaxStorage
		i.stores[si.ID].info.CanSeal = si.CanSeal
		i.stores[si.ID].info.CanStore = si.CanStore
		i.stores[si.ID].info.Groups = si.Groups
		i.stores[si.ID].info.AllowTo = si.AllowTo
		i.stores[si.ID].info.AllowTypes = allow
		i.stores[si.ID].info.DenyTypes = deny

		return nil
	}
	i.stores[si.ID] = &storageEntry{
		info: &si,
		fsi:  st,

		lastHeartbeat: time.Now(),
	}
	return nil
}

func (i *Index) StorageDetach(ctx context.Context, id storiface.ID, url string) error {
	i.lk.Lock()
	defer i.lk.Unlock()

	// ent: *storageEntry
	ent, ok := i.stores[id]
	if !ok {
		return xerrors.Errorf("storage '%s' isn't registered", id)
	}

	// check if this is the only path provider/url for this pathID
	drop := true
	if len(ent.info.URLs) > 0 {
		drop = len(ent.info.URLs) == 1 // only one url

		if drop && ent.info.URLs[0] != url {
			return xerrors.Errorf("not dropping path, requested and index urls don't match ('%s' != '%s')", url, ent.info.URLs[0])
		}
	}

	if drop {
		if a, hasAlert := i.pathAlerts[id]; hasAlert && i.alerting != nil {
			if i.alerting.IsRaised(a) {
				i.alerting.Resolve(a, map[string]string{
					"message": "path detached",
				})
			}
			delete(i.pathAlerts, id)
		}

		// stats
		var droppedEntries, primaryEntries, droppedDecls int

		// drop declarations
		for decl, dms := range i.sectors {
			var match bool
			for _, dm := range dms {
				if dm.storage == id {
					match = true
					droppedEntries++
					if dm.primary {
						primaryEntries++
					}
					break
				}
			}

			// if no entries match, nothing to do here
			if !match {
				continue
			}

			// if there's a match, and only one entry, drop the whole declaration
			if len(dms) <= 1 {
				delete(i.sectors, decl)
				droppedDecls++
				continue
			}

			// rewrite entries with the path we're dropping filtered out
			filtered := make([]*declMeta, 0, len(dms)-1)
			for _, dm := range dms {
				if dm.storage != id {
					filtered = append(filtered, dm)
				}
			}

			i.sectors[decl] = filtered
		}

		delete(i.stores, id)

		log.Warnw("Dropping sector storage", "path", id, "url", url, "droppedEntries", droppedEntries, "droppedPrimaryEntries", primaryEntries, "droppedDecls", droppedDecls)
	} else {
		newUrls := make([]string, 0, len(ent.info.URLs))
		for _, u := range ent.info.URLs {
			if u != url {
				newUrls = append(newUrls, u)
			}
		}
		ent.info.URLs = newUrls

		log.Warnw("Dropping sector path endpoint", "path", id, "url", url)
	}

	return nil
}

func (i *Index) StorageReportHealth(ctx context.Context, id storiface.ID, report storiface.HealthReport) error {
	i.lk.Lock()
	defer i.lk.Unlock()

	ent, ok := i.stores[id]
	if !ok {
		return xerrors.Errorf("health report for unknown storage: %s", id)
	}

	ent.fsi = report.Stat
	if report.Err != "" {
		ent.heartbeatErr = errors.New(report.Err)
	} else {
		ent.heartbeatErr = nil
	}
	ent.lastHeartbeat = time.Now()

	if report.Stat.Capacity > 0 {
		ctx, _ = tag.New(ctx, tag.Upsert(metrics.StorageID, string(id)))

		stats.Record(ctx, metrics.StorageFSAvailable.M(float64(report.Stat.FSAvailable)/float64(report.Stat.Capacity)))
		stats.Record(ctx, metrics.StorageAvailable.M(float64(report.Stat.Available)/float64(report.Stat.Capacity)))
		stats.Record(ctx, metrics.StorageReserved.M(float64(report.Stat.Reserved)/float64(report.Stat.Capacity)))

		stats.Record(ctx, metrics.StorageCapacityBytes.M(report.Stat.Capacity))
		stats.Record(ctx, metrics.StorageFSAvailableBytes.M(report.Stat.FSAvailable))
		stats.Record(ctx, metrics.StorageAvailableBytes.M(report.Stat.Available))
		stats.Record(ctx, metrics.StorageReservedBytes.M(report.Stat.Reserved))

		if report.Stat.Max > 0 {
			stats.Record(ctx, metrics.StorageLimitUsed.M(float64(report.Stat.Used)/float64(report.Stat.Max)))
			stats.Record(ctx, metrics.StorageLimitUsedBytes.M(report.Stat.Used))
			stats.Record(ctx, metrics.StorageLimitMaxBytes.M(report.Stat.Max))
		}
	}

	return nil
}

func (i *Index) StorageDeclareSector(ctx context.Context, storageID storiface.ID, s abi.SectorID, ft storiface.SectorFileType, primary bool) error {
	i.lk.Lock()
	defer i.lk.Unlock()

loop:
	for _, fileType := range storiface.PathTypes {
		if fileType&ft == 0 {
			continue
		}

		d := storiface.Decl{SectorID: s, SectorFileType: fileType}

		for _, sid := range i.sectors[d] {
			if sid.storage == storageID {
				if !sid.primary && primary {
					sid.primary = true
				} else {
					//log.Warnf("sector %v redeclared in %s", s, storageID) //yungojs
				}
				continue loop
			}
		}

		i.sectors[d] = append(i.sectors[d], &declMeta{
			storage: storageID,
			primary: primary,
		})
	}

	return nil
}

func (i *Index) StorageDropSector(ctx context.Context, storageID storiface.ID, s abi.SectorID, ft storiface.SectorFileType) error {
	i.lk.Lock()
	defer i.lk.Unlock()

	for _, fileType := range storiface.PathTypes {
		if fileType&ft == 0 {
			continue
		}

		d := storiface.Decl{SectorID: s, SectorFileType: fileType}

		if len(i.sectors[d]) == 0 {
			continue
		}

		rewritten := make([]*declMeta, 0, len(i.sectors[d])-1)
		for _, sid := range i.sectors[d] {
			if sid.storage == storageID {
				continue
			}

			rewritten = append(rewritten, sid)
		}
		if len(rewritten) == 0 {
			delete(i.sectors, d)
			continue
		}

		i.sectors[d] = rewritten
	}

	return nil
}

func (i *Index) StorageFindSector(ctx context.Context, s abi.SectorID, ft storiface.SectorFileType, ssize abi.SectorSize, allowFetch bool) ([]storiface.SectorStorageInfo, error) {
	i.lk.RLock()
	defer i.lk.RUnlock()

	storageIDs := map[storiface.ID]uint64{}
	isprimary := map[storiface.ID]bool{}

	allowTo := map[storiface.Group]struct{}{}

	for _, pathType := range storiface.PathTypes {
		if ft&pathType == 0 {
			continue
		}

		for _, id := range i.sectors[storiface.Decl{SectorID: s, SectorFileType: pathType}] {
			storageIDs[id.storage]++
			isprimary[id.storage] = isprimary[id.storage] || id.primary
		}
	}

	out := make([]storiface.SectorStorageInfo, 0, len(storageIDs))

	for id, n := range storageIDs {
		st, ok := i.stores[id]
		if !ok {
			log.Warnf("storage %s is not present in sector index (referenced by sector %v)", id, s)
			continue
		}

		urls, burls := make([]string, len(st.info.URLs)), make([]string, len(st.info.URLs))
		for k, u := range st.info.URLs {
			rl, err := url.Parse(u)
			if err != nil {
				return nil, xerrors.Errorf("failed to parse url: %w", err)
			}

			rl.Path = gopath.Join(rl.Path, ft.String(), storiface.SectorName(s))
			urls[k] = rl.String()
			burls[k] = u
		}

		if allowTo != nil && len(st.info.AllowTo) > 0 {
			for _, group := range st.info.AllowTo {
				allowTo[group] = struct{}{}
			}
		} else {
			allowTo = nil // allow to any
		}

		out = append(out, storiface.SectorStorageInfo{
			ID:       id,
			URLs:     urls,
			BaseURLs: burls,
			Weight:   st.info.Weight * n, // storage with more sector types is better

			CanSeal:  st.info.CanSeal,
			CanStore: st.info.CanStore,

			Primary: isprimary[id],

			AllowTypes: st.info.AllowTypes,
			DenyTypes:  st.info.DenyTypes,
		})
	}
	//yungojs
	return out, nil
	if allowFetch {
		spaceReq, err := ft.SealSpaceUse(ssize)
		if err != nil {
			return nil, xerrors.Errorf("estimating required space: %w", err)
		}

		for id, st := range i.stores {
			if !st.info.CanSeal {
				continue
			}

			if spaceReq > uint64(st.fsi.Available) {
				log.Debugf("not selecting on %s, out of space (available: %d, need: %d)", st.info.ID, st.fsi.Available, spaceReq)
				continue
			}

			if time.Since(st.lastHeartbeat) > SkippedHeartbeatThresh {
				log.Debugf("not selecting on %s, didn't receive heartbeats for %s", st.info.ID, time.Since(st.lastHeartbeat))
				continue
			}

			if st.heartbeatErr != nil {
				log.Debugf("not selecting on %s, heartbeat error: %s", st.info.ID, st.heartbeatErr)
				continue
			}

			if _, ok := storageIDs[id]; ok {
				continue
			}

			if !ft.AnyAllowed(st.info.AllowTypes, st.info.DenyTypes) {
				log.Debugf("not selecting on %s, not allowed by file type filters", st.info.ID)
				continue
			}

			if allowTo != nil {
				allow := false
				for _, group := range st.info.Groups {
					if _, found := allowTo[group]; found {
						log.Debugf("path %s in allowed group %s", st.info.ID, group)
						allow = true
						break
					}
				}

				if !allow {
					log.Debugf("not selecting on %s, not in allowed group, allow %+v; path has %+v", st.info.ID, allowTo, st.info.Groups)
					continue
				}
			}

			urls, burls := make([]string, len(st.info.URLs)), make([]string, len(st.info.URLs))
			for k, u := range st.info.URLs {
				rl, err := url.Parse(u)
				if err != nil {
					return nil, xerrors.Errorf("failed to parse url: %w", err)
				}

				rl.Path = gopath.Join(rl.Path, ft.String(), storiface.SectorName(s))
				urls[k] = rl.String()
				burls[k] = u
			}

			out = append(out, storiface.SectorStorageInfo{
				ID:       id,
				URLs:     urls,
				BaseURLs: burls,
				Weight:   st.info.Weight * 0, // TODO: something better than just '0'

				CanSeal:  st.info.CanSeal,
				CanStore: st.info.CanStore,

				Primary: false,

				AllowTypes: st.info.AllowTypes,
				DenyTypes:  st.info.DenyTypes,
			})
		}
	}

	return out, nil
}

func (i *Index) StorageInfo(ctx context.Context, id storiface.ID) (storiface.StorageInfo, error) {
	i.lk.RLock()
	defer i.lk.RUnlock()

	si, found := i.stores[id]
	if !found {
		return storiface.StorageInfo{}, xerrors.Errorf("sector store not found")
	}

	return *si.info, nil
}

func (i *Index) StorageBestAlloc(ctx context.Context, allocate storiface.SectorFileType, ssize abi.SectorSize, pathType storiface.PathType) ([]storiface.StorageInfo, error) {
	i.lk.RLock()
	defer i.lk.RUnlock()

	var candidates []storageEntry

	//var err error
	//var spaceReq uint64
	//switch pathType {
	//case storiface.PathSealing:
	//	spaceReq, err = allocate.SealSpaceUse(ssize)
	//case storiface.PathStorage:
	//	spaceReq, err = allocate.StoreSpaceUse(ssize)
	//default:
	//	panic(fmt.Sprintf("unexpected pathType: %s", pathType))
	//}
	//if err != nil {
	//	return nil, xerrors.Errorf("estimating required space: %w", err)
	//}

	for _, p := range i.stores {
		if (pathType == storiface.PathSealing) && !p.info.CanSeal {
			continue
		}
		if (pathType == storiface.PathStorage) && !p.info.CanStore {
			continue
		}
		//yungojs  34359738368  //32G
		if 207000000000 > uint64(p.fsi.Available) {
			//log.Debugf("not allocating on %s, out of space (available: %d, need: %d)", p.info.ID, p.fsi.Available, spaceReq)
			continue
		}
		//if spaceReq > uint64(p.fsi.Available) {
		//	log.Debugf("not allocating on %s, out of space (available: %d, need: %d)", p.info.ID, p.fsi.Available, spaceReq)
		//	continue
		//}

		//if time.Since(p.lastHeartbeat) > SkippedHeartbeatThresh {
		//	log.Debugf("not allocating on %s, didn't receive heartbeats for %s", p.info.ID, time.Since(p.lastHeartbeat))
		//	continue
		//}

		if p.heartbeatErr != nil {
			log.Debugf("not allocating on %s, heartbeat error: %s", p.info.ID, p.heartbeatErr)
			continue
		}

		candidates = append(candidates, *p)
	}

	if len(candidates) == 0 {
		return nil, xerrors.New("no good path found")
	}

	//sort.Slice(candidates, func(i, j int) bool {
	//	iw := big.Mul(big.NewInt(candidates[i].fsi.Available), big.NewInt(int64(candidates[i].info.Weight)))
	//	jw := big.Mul(big.NewInt(candidates[j].fsi.Available), big.NewInt(int64(candidates[j].info.Weight)))
	//
	//	return iw.GreaterThan(jw)
	//})
	//yungojs
	sort.Slice(candidates, func(ii, j int) bool {

		iw := big.NewInt(int64(candidates[ii].info.Weight))
		jw := big.NewInt(int64(candidates[j].info.Weight))
		return iw.Int.Cmp(jw.Int) < 0
	})

	out := make([]storiface.StorageInfo, len(candidates))
	for i, candidate := range candidates {
		out[i] = *candidate.info
	}

	return out, nil
}

func (i *Index) FindSector(id abi.SectorID, typ storiface.SectorFileType) ([]storiface.ID, error) {
	i.lk.RLock()
	defer i.lk.RUnlock()

	f, ok := i.sectors[storiface.Decl{
		SectorID:       id,
		SectorFileType: typ,
	}]
	if !ok {
		return nil, nil
	}
	out := make([]storiface.ID, 0, len(f))
	for _, meta := range f {
		out = append(out, meta.storage)
	}

	return out, nil
}

//yungojs
func (i *Index) StorageSetWeight(ctx context.Context, storageID storiface.ID) error {
	if _, ok := i.stores[storageID]; ok {
		i.stores[storageID].info.Weight += 1
		return nil
	}
	return errors.New("修改权重存储ID:" + string(storageID) + "不存在！")
}
func (i *Index) StorageLockByID(ctx context.Context, storageID storiface.ID, uid uuid.UUID) (int, error) {
	i.lk.Lock()
	defer i.lk.Unlock()
	num := 0
	if _, ok := i.stores[storageID]; ok {
		var rws []storageQueue
		for _, v := range i.stores[storageID].rw {
			if time.Since(v.requestTime) < storageTime {
				rws = append(rws, v)
			}
		}
		for in, v := range rws {
			if v.uid == uid {
				//更新请求时间，代表活跃
				rws[in].requestTime = time.Now()
				i.stores[storageID].rw = rws
				return num, nil
			}
			num++
		}
		var st storageQueue
		st.requestTime = time.Now()
		st.uid = uid
		//首次排队
		rws = append(rws, st)
		i.stores[storageID].rw = rws
		return num, nil
	}
	return num, errors.New("获取锁 存储ID:" + string(storageID) + "不存在！")
}
func (i *Index) StorageUnLockByID(ctx context.Context, storageID storiface.ID, uid uuid.UUID) error {
	i.lk.Lock()
	defer i.lk.Unlock()
	if _, ok := i.stores[storageID]; ok {
		for in, v := range i.stores[storageID].rw {
			if v.uid == uid {
				if in < len(i.stores[storageID].rw)-1 {
					i.stores[storageID].rw = append(i.stores[storageID].rw[:in], i.stores[storageID].rw[in+1:]...)
				} else {
					i.stores[storageID].rw = i.stores[storageID].rw[:in]
				}
				return nil
			}
		}
		return nil
	}
	return errors.New("释放锁 存储ID:" + string(storageID) + "不存在！")
}

var _ SectorIndex = &Index{}
