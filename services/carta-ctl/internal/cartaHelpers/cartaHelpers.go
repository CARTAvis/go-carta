package cartaHelpers

import (
	"encoding/binary"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
)

const IcdVersion = 30

type MessagePrefix struct {
	EventType  cartaDefinitions.EventType
	IcdVersion uint16
	RequestId  uint32
}

func DecodeMessagePrefix(data []byte) (prefix MessagePrefix, err error) {
	if len(data) < 8 {
		err = fmt.Errorf("message too short")
		return
	}

	prefix = MessagePrefix{
		EventType:  cartaDefinitions.EventType(binary.LittleEndian.Uint16(data[0:2])),
		IcdVersion: binary.LittleEndian.Uint16(data[2:4]),
		RequestId:  binary.LittleEndian.Uint32(data[4:8]),
	}
	if prefix.IcdVersion != IcdVersion {
		err = fmt.Errorf("invalid ICD version")
		return
	}
	return
}

func PrepareBinaryMessage(byteData []byte, eventType cartaDefinitions.EventType, requestId uint32) []byte {
	// Prepend 8 bytes: first 2 bytes is event Type, next 2 bytes is ICD version, last 4 bytes is request ID
	header := make([]byte, 8)
	binary.LittleEndian.PutUint16(header[0:2], uint16(eventType))
	binary.LittleEndian.PutUint16(header[2:4], IcdVersion)
	binary.LittleEndian.PutUint32(header[4:8], requestId)

	// Prepend header to byteData
	byteData = append(header, byteData...)
	return byteData
}

func PrepareMessagePayload(msg proto.Message, eventType cartaDefinitions.EventType, requestId uint32) ([]byte, error) {
	byteData, err := proto.Marshal(msg)
	if err != nil {
		fmt.Println("Error marshaling data:", err)
		return nil, err
	}
	return PrepareBinaryMessage(byteData, eventType, requestId), nil
}

// ExtractFileId This function attempts to extract the fileId from a protobuf message by determining whether the generic protobuf message
// has a GetFileId method. There's an inconsistency in terms of how we store file IDs. Sometimes they're uint32, other times int32, this
// function attempts to handle both cases.
func ExtractFileId(msg proto.Message) (int32, bool) {
	type fileIdGetter interface {
		GetFileId() int32
	}
	type fileIdGetterUint interface {
		GetFileId() uint32
	}

	if getter, ok := msg.(fileIdGetter); ok {
		return getter.GetFileId(), true
	}
	if getter, ok := msg.(fileIdGetterUint); ok {
		return int32(getter.GetFileId()), true
	}
	return -1, false
}

// messageTypeMap maps EventTypes to their corresponding message constructor functions
var messageTypeMap = map[cartaDefinitions.EventType]func() proto.Message{
	cartaDefinitions.EventType_OPEN_FILE:                     func() proto.Message { return &cartaDefinitions.OpenFile{} },
	cartaDefinitions.EventType_CLOSE_FILE:                    func() proto.Message { return &cartaDefinitions.CloseFile{} },
	cartaDefinitions.EventType_SET_IMAGE_CHANNELS:            func() proto.Message { return &cartaDefinitions.SetImageChannels{} },
	cartaDefinitions.EventType_SET_CURSOR:                    func() proto.Message { return &cartaDefinitions.SetCursor{} },
	cartaDefinitions.EventType_SET_SPATIAL_REQUIREMENTS:      func() proto.Message { return &cartaDefinitions.SetSpatialRequirements{} },
	cartaDefinitions.EventType_SET_HISTOGRAM_REQUIREMENTS:    func() proto.Message { return &cartaDefinitions.SetHistogramRequirements{} },
	cartaDefinitions.EventType_SET_STATS_REQUIREMENTS:        func() proto.Message { return &cartaDefinitions.SetStatsRequirements{} },
	cartaDefinitions.EventType_SET_SPECTRAL_REQUIREMENTS:     func() proto.Message { return &cartaDefinitions.SetSpectralRequirements{} },
	cartaDefinitions.EventType_SET_REGION:                    func() proto.Message { return &cartaDefinitions.SetRegion{} },
	cartaDefinitions.EventType_REMOVE_REGION:                 func() proto.Message { return &cartaDefinitions.RemoveRegion{} },
	cartaDefinitions.EventType_IMPORT_REGION:                 func() proto.Message { return &cartaDefinitions.ImportRegion{} },
	cartaDefinitions.EventType_EXPORT_REGION:                 func() proto.Message { return &cartaDefinitions.ExportRegion{} },
	cartaDefinitions.EventType_SET_CONTOUR_PARAMETERS:        func() proto.Message { return &cartaDefinitions.SetContourParameters{} },
	cartaDefinitions.EventType_CONCAT_STOKES_FILES:           func() proto.Message { return &cartaDefinitions.ConcatStokesFiles{} },
	cartaDefinitions.EventType_MOMENT_REQUEST:                func() proto.Message { return &cartaDefinitions.MomentRequest{} },
	cartaDefinitions.EventType_STOP_MOMENT_CALC:              func() proto.Message { return &cartaDefinitions.StopMomentCalc{} },
	cartaDefinitions.EventType_SAVE_FILE:                     func() proto.Message { return &cartaDefinitions.SaveFile{} },
	cartaDefinitions.EventType_PV_REQUEST:                    func() proto.Message { return &cartaDefinitions.PvRequest{} },
	cartaDefinitions.EventType_STOP_PV_CALC:                  func() proto.Message { return &cartaDefinitions.StopPvCalc{} },
	cartaDefinitions.EventType_FITTING_REQUEST:               func() proto.Message { return &cartaDefinitions.FittingRequest{} },
	cartaDefinitions.EventType_STOP_FITTING:                  func() proto.Message { return &cartaDefinitions.StopFitting{} },
	cartaDefinitions.EventType_REMOTE_FILE_REQUEST:           func() proto.Message { return &cartaDefinitions.RemoteFileRequest{} },
	cartaDefinitions.EventType_ADD_REQUIRED_TILES:            func() proto.Message { return &cartaDefinitions.AddRequiredTiles{} },
	cartaDefinitions.EventType_REMOVE_REQUIRED_TILES:         func() proto.Message { return &cartaDefinitions.RemoveRequiredTiles{} },
	cartaDefinitions.EventType_SET_VECTOR_OVERLAY_PARAMETERS: func() proto.Message { return &cartaDefinitions.SetVectorOverlayParameters{} },
	cartaDefinitions.EventType_START_ANIMATION:               func() proto.Message { return &cartaDefinitions.StartAnimation{} },
	cartaDefinitions.EventType_STOP_ANIMATION:                func() proto.Message { return &cartaDefinitions.StopAnimation{} },
	cartaDefinitions.EventType_ANIMATION_FLOW_CONTROL:        func() proto.Message { return &cartaDefinitions.AnimationFlowControl{} },
	cartaDefinitions.EventType_CHANNEL_MAP_FLOW_CONTROL:      func() proto.Message { return &cartaDefinitions.ChannelMapFlowControl{} },
	cartaDefinitions.EventType_OPEN_CATALOG_FILE:             func() proto.Message { return &cartaDefinitions.OpenCatalogFile{} },
	cartaDefinitions.EventType_CLOSE_CATALOG_FILE:            func() proto.Message { return &cartaDefinitions.CloseCatalogFile{} },
	cartaDefinitions.EventType_CATALOG_FILTER_REQUEST:        func() proto.Message { return &cartaDefinitions.CatalogFilterRequest{} },
}

// UnmarshalMessage Un-marshals raw message bytes into the appropriate protobuf message type based on EventType
func UnmarshalMessage(eventType cartaDefinitions.EventType, rawMsg []byte) (proto.Message, error) {
	// Look up the message constructor in the map
	constructor, ok := messageTypeMap[eventType]
	if !ok {
		return nil, fmt.Errorf("unknown event type: %v", eventType)
	}

	// Create a new message instance
	msg := constructor()

	// Unmarshal the message
	err := proto.Unmarshal(rawMsg, msg)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

// ExtractFileIdFromBytes attempts to extract the fileId from raw message bytes.
// It un-marshals the message based on the EventType and then extracts the fileId.
// Returns the fileId and true if found, or 0 and false if not found or if the message type doesn't have a fileId.
func ExtractFileIdFromBytes(eventType cartaDefinitions.EventType, rawMsg []byte) (int32, bool) {
	msg, err := UnmarshalMessage(eventType, rawMsg)
	if err != nil {
		return -1, false
	}
	// Extract fileId from the unmarshaled message
	return ExtractFileId(msg)
}
