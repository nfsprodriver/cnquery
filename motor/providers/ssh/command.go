package ssh

import (
	"bytes"
	"errors"
	"time"

	"github.com/rs/zerolog/log"

	"go.mondoo.io/mondoo/motor/providers"
	"golang.org/x/crypto/ssh"
)

type Command struct {
	providers.Command
	SSHTransport *SSHTransport
}

func (c *Command) Exec(command string) (*providers.Command, error) {
	c.Command.Command = command
	c.Command.Stats.Duration = time.Since(c.Command.Stats.Start)

	stdoutBuffer := &bytes.Buffer{}
	stderrBuffer := &bytes.Buffer{}

	c.Command.Stdout = stdoutBuffer
	c.Command.Stderr = stderrBuffer

	if c.SSHTransport.SSHClient == nil {
		return nil, errors.New("ssh session not established")
	}

	session, err := c.SSHTransport.SSHClient.NewSession()
	if err != nil {
		log.Debug().Msg("could not open new session, try to re-establish connection")
		err = c.SSHTransport.Reconnect()
		if err != nil {
			return nil, err
		}

		session, err = c.SSHTransport.SSHClient.NewSession()
		if err != nil {
			return nil, err
		}
	}
	defer session.Close()

	// start ssh call
	session.Stdout = stdoutBuffer
	session.Stderr = stderrBuffer
	err = session.Run(c.Command.Command)
	c.Command.Stats.Duration = time.Since(c.Command.Stats.Start)

	// command completed successfully, great :-)
	if err == nil {
		return &c.Command, nil
	}

	// if the program failed, we do not return err but its exit code
	var e *ssh.ExitError
	match := errors.As(err, &e)
	if match {
		c.Command.ExitStatus = e.ExitStatus()
		return &c.Command, nil
	}

	// all other errors are real errors and not expected
	return &c.Command, err
}