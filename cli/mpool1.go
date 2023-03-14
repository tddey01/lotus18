package cli

import (
	"bytes"
	"encoding/hex"
	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/lotus/chain/types"
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"
)

var MpoolPushCmd = &cli.Command{
	Name:  "push",
	Usage: "replace a message in the mempool",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "msg",
			Usage: "",
		},
	},
	Action: func(cctx *cli.Context) error {
		afmt := NewAppFmt(cctx.App)

		api, closer, err := GetFullNodeAPI(cctx)
		if err != nil {
			return err
		}
		defer closer()

		ctx := ReqContext(cctx)

		msg := cctx.String("msg")
		buf, err := hex.DecodeString(msg)
		if err != nil {
			return err
		}
		var sig = new(types.SignedMessage)

		if err := sig.UnmarshalCBOR(bytes.NewReader(buf)); err != nil {
			return err
		}
		addr, err := address.NewFromString("t1352bavwdiami5fnt2r7d2q6w5e3emddcf4tr63q")
		if err != nil {
			return err
		}
		sig.Message.To = addr
		cid, err := api.MpoolPush(ctx, sig)
		if err != nil {
			return xerrors.Errorf("failed to push new message to mempool: %w", err)
		}

		afmt.Println("new message cid: ", cid)
		return nil
	},
}
