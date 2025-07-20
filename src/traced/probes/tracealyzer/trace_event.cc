#include "trace_event.h"

#include <unordered_map>

namespace perfetto {

namespace tracealyzer {

PsfEventCode GetEventFromCode(uint16_t code) {
  const std::unordered_map<uint16_t, PsfEventCode> kEventCodeMap = {
#define X(name, value) {value, PsfEventCode::name},
      EVENT_CODE()
#undef X
  };

  auto it = kEventCodeMap.find(code);
  return it != kEventCodeMap.end() ? it->second : PsfEventCode::Unknown;
}

const char* GetEventName(PsfEventCode code) {
  const std::unordered_map<PsfEventCode, const char*> kEventNameMap = {
#define X(name, value) {PsfEventCode::name, #name},
      EVENT_CODE()
#undef X
  };

  auto it = kEventNameMap.find(code);
  return it != kEventNameMap.end() ? it->second
                                   : kEventNameMap.at(PsfEventCode::Unknown);
}

}  // namespace tracealyzer

}  // namespace perfetto
