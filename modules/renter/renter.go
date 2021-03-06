package renter

import (
	"log"

	"github.com/NebulousLabs/Sia/modules"
	"github.com/NebulousLabs/Sia/modules/renter/hostdb"
	"github.com/NebulousLabs/Sia/sync"
	"github.com/NebulousLabs/Sia/types"
)

// A hostDB is a database of hosts that the renter can use for figuring out who
// to upload to, and download from.
type hostDB interface {
	// ActiveHosts returns the list of hosts that are actively being selected
	// from.
	ActiveHosts() []modules.HostSettings

	// AllHosts returns the full list of hosts known to the hostdb.
	AllHosts() []modules.HostSettings

	// AveragePrice returns the average price of a host.
	AveragePrice() types.Currency

	// NewPool returns a new HostPool, which can negotiate contracts with
	// hosts. The size and duration of these contracts are supplied as
	// arguments.
	NewPool(filesize uint64, duration types.BlockHeight) (hostdb.HostPool, error)

	// Renew renews a file contract, returning the new contract ID.
	Renew(id types.FileContractID, newHeight types.BlockHeight) (types.FileContractID, error)
}

// A trackedFile contains metadata about files being tracked by the Renter.
// Tracked files are actively repaired by the Renter.  By default, files
// uploaded by the user are tracked, and files that are added (via loading a
// .sia file) are not.
type trackedFile struct {
	// location of original file on disk
	RepairPath string
	// height at which file contracts should end
	EndHeight types.BlockHeight
	// whether the file should be renewed (overrides EndHeight if true)
	Renew bool
}

// A Renter is responsible for tracking all of the files that a user has
// uploaded to Sia, as well as the locations and health of these files.
type Renter struct {
	// modules
	cs     modules.ConsensusSet
	wallet modules.Wallet

	// resources
	hostDB hostDB
	log    *log.Logger

	// variables
	files         map[string]*file
	tracking      map[string]trackedFile // map from nickname to metadata
	downloadQueue []*download

	// constants
	persistDir string

	mu *sync.RWMutex
}

// New returns an empty renter.
func New(cs modules.ConsensusSet, wallet modules.Wallet, tpool modules.TransactionPool, persistDir string) (*Renter, error) {
	hdb, err := hostdb.New(cs, wallet, tpool, persistDir)
	if err != nil {
		return nil, err
	}

	r := &Renter{
		cs:     cs,
		wallet: wallet,
		hostDB: hdb,

		files:    make(map[string]*file),
		tracking: make(map[string]trackedFile),

		persistDir: persistDir,
		mu:         sync.New(modules.SafeMutexDelay, 1),
	}
	err = r.initPersist()
	if err != nil {
		return nil, err
	}

	go r.threadedRepairLoop()

	return r, nil
}

// hostdb passthroughs
func (r *Renter) ActiveHosts() []modules.HostSettings { return r.hostDB.ActiveHosts() }
func (r *Renter) AllHosts() []modules.HostSettings    { return r.hostDB.AllHosts() }

// enforce that Renter satisfies the modules.Renter interface
var _ modules.Renter = (*Renter)(nil)
