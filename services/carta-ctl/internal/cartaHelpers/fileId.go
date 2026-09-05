package cartaHelpers

import (
	"fmt"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/CARTAvis/go-carta/pkg/cartaDefinitions"
)

// fileIdField is the protobuf field naming the image a message is about.
const fileIdField protoreflect.Name = "file_id"

var messageTypeCache sync.Map // cartaDefinitions.EventType -> protoreflect.MessageType

// messageTypeFor resolves the protobuf type carried by an event. Event names
// and message names differ only in case convention, so the mapping needs no
// table: CARTA.RasterTileData carries RASTER_TILE_DATA. Events whose type
// cannot be resolved (the enum has a few names that do not follow the
// convention) simply have no type, and callers leave those messages alone.
func messageTypeFor(eventType cartaDefinitions.EventType) protoreflect.MessageType {
	if cached, ok := messageTypeCache.Load(eventType); ok {
		mt, _ := cached.(protoreflect.MessageType)
		return mt
	}
	var name strings.Builder
	name.WriteString("CARTA.")
	for _, word := range strings.Split(eventType.String(), "_") {
		if word == "" {
			continue
		}
		name.WriteString(strings.ToUpper(word[:1]))
		name.WriteString(strings.ToLower(word[1:]))
	}
	mt, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName(name.String()))
	if err != nil {
		mt = nil
	}
	messageTypeCache.Store(eventType, mt)
	return mt
}

func fileIdDescriptor(msg protoreflect.Message) protoreflect.FieldDescriptor {
	fd := msg.Descriptor().Fields().ByName(fileIdField)
	if fd == nil || fd.IsList() || fd.IsMap() {
		return nil
	}
	switch fd.Kind() {
	case protoreflect.Int32Kind, protoreflect.Sfixed32Kind, protoreflect.Sint32Kind,
		protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return fd
	default:
		return nil
	}
}

func fileIdValue(msg protoreflect.Message, fd protoreflect.FieldDescriptor) int32 {
	switch fd.Kind() {
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return int32(msg.Get(fd).Uint())
	default:
		return int32(msg.Get(fd).Int())
	}
}

func setFileIdValue(msg protoreflect.Message, fd protoreflect.FieldDescriptor, fileId int32) {
	switch fd.Kind() {
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		msg.Set(fd, protoreflect.ValueOfUint32(uint32(fileId)))
	default:
		msg.Set(fd, protoreflect.ValueOfInt32(fileId))
	}
}

// SetFileId replaces the file id of a message, whatever its type. It reports
// false for messages that name no image.
func SetFileId(msg proto.Message, fileId int32) bool {
	reflected := msg.ProtoReflect()
	fd := fileIdDescriptor(reflected)
	if fd == nil {
		return false
	}
	setFileIdValue(reflected, fd, fileId)
	return true
}

// FileIdFromBytes reads the file id out of an encoded message.
func FileIdFromBytes(eventType cartaDefinitions.EventType, rawMsg []byte) (int32, bool) {
	mt := messageTypeFor(eventType)
	if mt == nil {
		return 0, false
	}
	msg := mt.New()
	fd := fileIdDescriptor(msg)
	if fd == nil {
		return 0, false
	}
	if err := proto.Unmarshal(rawMsg, msg.Interface()); err != nil {
		return 0, false
	}
	return fileIdValue(msg, fd), true
}

// RewriteFileId re-encodes a message with a different file id.
func RewriteFileId(eventType cartaDefinitions.EventType, rawMsg []byte, fileId int32) ([]byte, error) {
	mt := messageTypeFor(eventType)
	if mt == nil {
		return nil, fmt.Errorf("no message type for %v", eventType)
	}
	msg := mt.New()
	fd := fileIdDescriptor(msg)
	if fd == nil {
		return nil, fmt.Errorf("%v names no file", eventType)
	}
	if err := proto.Unmarshal(rawMsg, msg.Interface()); err != nil {
		return nil, err
	}
	setFileIdValue(msg, fd, fileId)
	return proto.Marshal(msg.Interface())
}
