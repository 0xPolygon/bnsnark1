package types

type BLS interface {
	NewSK() SK
	NewG1() G1
	NewG2() G2

	RandomSK() SK

	G2Generator() G2

	HashToG1([]byte) (G1, error)

	VerifyOpt(pk G2, mp, sig G1) bool
}

type SK interface {
	Serialize() []byte
	Deserialize([]byte) error
}

type G1 interface {
	Add(G1) G1
	Mul(SK) G1
	Serialize() []byte
	Deserialize([]byte) error
}

type G2 interface {
	Add(G2) G2
	Mul(SK) G2
	Serialize() []byte
	Deserialize([]byte) error

	Marshall() []byte // TODO: how / why different from Serialize?
}
