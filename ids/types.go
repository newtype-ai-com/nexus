package ids

// Distinct named types prevent mixing session, task and other identifiers.
type Account string
type Session string
type Delegation string
type Task string
type Policy string
type Event string
type Approval string
type Run string
type Conv string
type Action string
type Invocation string
type Login string
type Audit string
type Process string
type Doc string
type Team string
type Seat string

func parse[T ~string](kind Kind, value string) (T, error) {
	if err := Check(kind, value); err != nil {
		return "", err
	}
	return T(value), nil
}
func ParseAccount(s string) (Account, error)       { return parse[Account](KindAccount, s) }
func ParseSession(s string) (Session, error)       { return parse[Session](KindSession, s) }
func ParseDelegation(s string) (Delegation, error) { return parse[Delegation](KindDelegation, s) }
func ParseTask(s string) (Task, error)             { return parse[Task](KindTask, s) }
func ParsePolicy(s string) (Policy, error)         { return parse[Policy](KindPolicy, s) }
func ParseEvent(s string) (Event, error)           { return parse[Event](KindEvent, s) }
func ParseApproval(s string) (Approval, error)     { return parse[Approval](KindApproval, s) }
func ParseRun(s string) (Run, error)               { return parse[Run](KindRun, s) }
func ParseConv(s string) (Conv, error)             { return parse[Conv](KindConv, s) }
func ParseAction(s string) (Action, error)         { return parse[Action](KindAction, s) }
func ParseInvocation(s string) (Invocation, error) { return parse[Invocation](KindInvocation, s) }
func ParseLogin(s string) (Login, error)           { return parse[Login](KindLogin, s) }
func ParseAudit(s string) (Audit, error)           { return parse[Audit](KindAudit, s) }
func ParseProcess(s string) (Process, error)       { return parse[Process](KindProcess, s) }
func ParseDoc(s string) (Doc, error)               { return parse[Doc](KindDoc, s) }
func ParseTeam(s string) (Team, error)             { return parse[Team](KindTeam, s) }
func ParseSeat(s string) (Seat, error)             { return parse[Seat](KindSeat, s) }
