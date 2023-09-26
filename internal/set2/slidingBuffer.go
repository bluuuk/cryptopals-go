package set

import "errors"

type SlidingBuffer struct {
	buffer              []byte
	start, windowLength int
}

func NewSlidingBuffer(buffer []byte, windowLength int) *SlidingBuffer {

	if buffer == nil {
		buffer = make([]byte, 0)
	}

	return &SlidingBuffer{
		buffer:       buffer,
		start:        0,
		windowLength: windowLength,
	}
}

func (sb *SlidingBuffer) Append(b byte) {
	sb.buffer = append(sb.buffer, b)
}

func (sb *SlidingBuffer) AdvanceWindow(steps int) error {
	if sb.start+steps+sb.windowLength > len(sb.buffer) {
		return errors.New("buffer not big enough")
	}
	sb.start = sb.start + steps
	return nil

}

func (sb *SlidingBuffer) Window() ([]byte, error) {
	if len(sb.buffer) < sb.windowLength {
		return nil, errors.New("buffer not filled for current window length")
	}
	buffer := make([]byte, sb.windowLength)
	copy(buffer, sb.buffer[sb.start:sb.start+sb.windowLength])
	return buffer, nil
}

func (sb *SlidingBuffer) GetBuffer() []byte {
	return sb.buffer
}
