package storage

import "strconv"

// MaxFleet is how many devices the server manages: device lists and
// exports, alert and health monitoring, fleet views, reports and active
// update jobs cover the newest MaxFleet devices (load-tested at 2,000).
const MaxFleet = 5000

// fleetLimit ends a device query at MaxFleet rows.
var fleetLimit = " LIMIT " + strconv.Itoa(MaxFleet)
