package core

// BackgroundCompletion is a terminal command result, not an instruction or a
// capability. Producers must redact Output before publishing. Empty Status
// releases a reservation without notification (e.g. a foreground command).
// JobID is stable even if the OS reuses a PID.
type BackgroundCompletion struct {
	JobID    string `json:"job_id"`
	PID      int    `json:"pid"`
	Status   string `json:"status"` // succeeded, failed, timed_out, stopped
	ExitCode int    `json:"exit_code"`
	Output   string `json:"output"`
}

// BackgroundRegister reserves one completion slot. The returned callback is
// safe after the originating turn ends; call it exactly once, including on
// startup failure (empty Status). It must not call ToolContext.Emit, Approve or
// Secret after Run returns. A nil register means notifications are disabled.
type BackgroundRegister func() (func(BackgroundCompletion), error)
