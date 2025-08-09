#include "tracealyzer_data_source.h"

#include "perfetto/ext/base/file_utils.h"
#include "protos/perfetto/config/tracealyzer/tracealyzer_config.pbzero.h"
#include "protos/perfetto/trace/trace_packet.pbzero.h"
#include "protos/perfetto/trace/track_event/process_descriptor.pbzero.h"
#include "protos/perfetto/trace/track_event/thread_descriptor.pbzero.h"
#include "protos/perfetto/trace/track_event/track_descriptor.pbzero.h"

#include <unistd.h>

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch-enum"
#endif

namespace {
constexpr uint32_t kProcessId = 1001;  // Assuming process ID is 1001.
constexpr const char* kProcessName = "MCU Process";
}  // namespace

namespace perfetto {

namespace tracealyzer {

template <>
struct FromFileTraits<TraceTimestampData> {
  static TraceTimestampData::RawTimestampData& GetInner(
      TraceTimestampData& ttd) {
    return ttd.inner_;
  }
};

template <class T>
FromFile<T>::~FromFile() = default;

template <class T>
std::unique_ptr<T> FromFile<T>::ReadFromFile(base::ScopedFile& file) {
  auto instance = std::unique_ptr<T>(new T());
  if (!instance->Read(file)) {
    return nullptr;
  }
  return instance;
}

template <class T>
bool FromFile<T>::Read(base::ScopedFile& file) {
  auto& inner = FromFileTraits<T>::GetInner(*static_cast<T*>(this));

  if (base::Read(*file, &inner, sizeof(inner)) != sizeof(inner)) {
    PERFETTO_ELOG("Failed to read TraceHeader from file.");
    return false;
  }

  return true;
}

TraceHeader::~TraceHeader() = default;

bool TraceHeader::Read(base::ScopedFile& file) {
  RawHeader raw_header;

  if (base::Read(*file, &raw_header, sizeof(raw_header)) !=
      sizeof(raw_header)) {
    PERFETTO_ELOG("Failed to read TraceHeader from file.");
    return false;
  }

  if (raw_header.uiPSF != kTraceHeaderMagic) {
    PERFETTO_ELOG("Invalid TraceHeader magic number.");
    return false;
  }

  inner_ = raw_header;
  return true;
}

TraceTimestampData::~TraceTimestampData() = default;

TraceEntryTable::~TraceEntryTable() = default;

bool TraceEntryTable::Read(base::ScopedFile& file) {
  if (base::Read(*file, &uxSlots, sizeof(uxSlots)) != sizeof(uxSlots) ||
      base::Read(*file, &uxEntrySymbolLength, sizeof(uxEntrySymbolLength)) !=
          sizeof(uxEntrySymbolLength) ||
      base::Read(*file, &uxEntryStateCount, sizeof(uxEntryStateCount)) !=
          sizeof(uxEntryStateCount)) {
    PERFETTO_ELOG("Failed to read TraceEntryTable header.");
    return false;
  }

  axEntries.resize(uxSlots);
  for (auto& entry : axEntries) {
    entry.xStates.resize(uxEntryStateCount);

    if (base::Read(*file, &entry.pvAddress, sizeof(entry.pvAddress)) !=
            sizeof(entry.pvAddress) ||
        base::Read(*file, entry.xStates.data(),
                   uxEntryStateCount * sizeof(TraceUnsignedBaseType_t)) !=
            static_cast<ssize_t>(uxEntryStateCount *
                                 sizeof(TraceUnsignedBaseType_t)) ||
        base::Read(*file, &entry.uiOptions, sizeof(entry.uiOptions)) !=
            sizeof(entry.uiOptions) ||
        base::Read(*file, entry.szSymbol.data(),
                   uxEntrySymbolLength * sizeof(char)) !=
            static_cast<ssize_t>(uxEntrySymbolLength * sizeof(char))) {
      PERFETTO_ELOG("Failed to read TraceEntryTable entries.");
      return false;
    }
  }
  return true;
}

TraceEvent::~TraceEvent() = default;

bool TraceEvent::Read(base::ScopedFile& file) {
  uint16_t event_id;
  uint8_t args_count;

  if (base::Read(*file, &event_id, sizeof(event_id)) != sizeof(event_id) ||
      base::Read(*file, &event_count_, sizeof(event_count_)) !=
          sizeof(event_count_) ||
      base::Read(*file, &timestamp_, sizeof(timestamp_)) !=
          sizeof(timestamp_)) {
    PERFETTO_ELOG("Failed to read TraceEvent header.");
    return false;
  }

  args_count = event_id >> 12;
  event_id = event_id & 0xFFF;  // Shift to get the event code.

  event_ = GetEventFromCode(event_id);
  if (event_ == PsfEventCode::Unknown) {
    PERFETTO_DLOG("Unknown event code: 0x%x, read pos: 0x%lx", event_id,
                  static_cast<uint64_t>(lseek64(file.get(), 0, SEEK_CUR)));
  }

  args_.resize(args_count);
  if (base::Read(*file, args_.data(),
                 args_count * sizeof(TraceUnsignedBaseType_t)) !=
      args_count * sizeof(TraceUnsignedBaseType_t)) {
    PERFETTO_ELOG("Failed to read TraceEvent arguments.");
    return false;
  }

  return true;
}

TraceObject::TraceObject(TraceUnsignedBaseType_t handle,
                         const std::string& name,
                         Type type,
                         TraceWriterPtr writer)
    : writer_(writer), handle_(handle), name_(name), type_(type) {}

TraceObject::~TraceObject() = default;

void TraceObject::AddTrackEvent(uint64_t timestamp,
                                TrackEventType type,
                                uint64_t event_track_uuid,
                                std::optional<std::string> name) {
  auto packet = writer_->NewTracePacket();
  packet->set_timestamp(timestamp);
  auto* trace_event = packet->set_track_event();
  trace_event->set_type(type);
  trace_event->set_track_uuid(event_track_uuid);
  if (name) {
    trace_event->set_name(*name);
  }
}

template <>
std::unique_ptr<Thread> TraceObject::FromEvent<Thread>(const TraceEvent& event,
                                                       TraceWriterPtr writer) {
  std::unique_ptr<Thread> thread(new Thread(
      event.Args()[0], "", event.Args()[1], event.Args()[2], writer));
  return thread;
}

Thread::~Thread() = default;

Thread::Thread(TraceUnsignedBaseType_t handle,
               const std::string& name,
               uint32_t stack_size,
               uint32_t prio,
               TraceWriterPtr writer)
    : TraceObject(handle, name, Type::Thread, writer),
      tid_(ThreadIdAllocator::Instance().NextThreadId()),
      stack_size_(stack_size),
      prio_(prio) {}

void Thread::ThreadReady(uint64_t timestamp) {
  AddTrackEvent(timestamp, TrackEventType::TYPE_INSTANT,
                TracealyzerDataSource::GenUuidFromTid(tid_),
                GetEventName(PsfEventCode::TaskReady));
}

void Thread::ThreadSchedIn(uint64_t timestamp) {
  AddTrackEvent(timestamp, TrackEventType::TYPE_SLICE_BEGIN,
                TracealyzerDataSource::GenUuidFromTid(tid_), GetObjectName());
}

void Thread::ThreadSchedOut(uint64_t timestamp) {
  AddTrackEvent(timestamp, TrackEventType::TYPE_SLICE_END,
                TracealyzerDataSource::GenUuidFromTid(tid_));
}

void Thread::Flush() {
  auto packet = writer_->NewTracePacket();

  packet->set_timestamp(0);  // Timestamp is not used for thread flush.
  auto* desc = packet->set_track_descriptor();
  desc->set_uuid(TracealyzerDataSource::GenUuidFromTid(GetThreadId()));
  auto* thread = desc->set_thread();
  thread->set_pid(kProcessId);
  thread->set_tid(GetThreadId());
  thread->set_thread_name(GetObjectName());
}

ThreadIdAllocator::ThreadIdAllocator() = default;

int32_t ThreadIdAllocator::NextThreadId() {
  return next_tid_++;
}

TraceObjectManager::TraceObjectManager(TraceWriterPtr writer)
    : writer_(writer) {}

template <typename T>
std::shared_ptr<T> TraceObjectManager::GetObject(
    TraceUnsignedBaseType_t handle) {
  auto it = objects_.find(handle);
  if (it != objects_.end()) {
    return std::static_pointer_cast<T>(it->second);
  }
  return nullptr;
}

void TraceObjectManager::AddObject(std::unique_ptr<TraceObject> object) {
  objects_[object->GetHandle()] = std::move(object);
}

void TraceObjectManager::ThreadActivate(std::shared_ptr<Thread> thread,
                                        uint64_t timestamp) {
  assert(thread);

  if (current_thread_) {
    current_thread_->ThreadSchedOut(timestamp);
  }

  current_thread_ = std::move(thread);
  current_thread_->ThreadSchedIn(timestamp);
}

void TraceObjectManager::Flush() {
  for (auto& pair : objects_) {
    pair.second->Flush();
  }
}
}  // namespace tracealyzer

using namespace tracealyzer;
using protos::pbzero::TracealyzerConfig;

// static
const ProbesDataSource::Descriptor TracealyzerDataSource::descriptor = {
    /* name */ "tracealyzer",
    /* flags */ Descriptor::kFlagsNone,
    /* fill_descriptor_func */ nullptr,
};

TracealyzerDataSource::TracealyzerDataSource(
    base::TaskRunner* task_runner,
    const DataSourceConfig& ds_config,
    TracingSessionID session_id,
    std::unique_ptr<TraceWriter> writer)
    : ProbesDataSource(session_id, &descriptor),
      task_runner_(task_runner),
      writer_(std::move(writer)),
      trace_object_manager_(this->writer_) {
  TracealyzerConfig::Decoder cfg(ds_config.tracealyzer_config_raw());

  if (cfg.has_file_path()) {
    trace_file_ = base::OpenFile(cfg.file_path().ToStdString(), O_RDONLY);
    if (!trace_file_) {
      PERFETTO_ELOG("Failed to open trace file for Tracealyzer data source: %s",
                    cfg.file_path().data);
    }
  }
}

bool TracealyzerDataSource::ReadTraceHeader(base::ScopedFile& file) {
  // Read the trace header.
  trace_header_ = TraceHeader::ReadFromFile(file);
  if (!trace_header_) {
    PERFETTO_ELOG("Failed to read Tracealyzer trace header.");
    return false;
  }

  trace_timestamp_ = TraceTimestampData::ReadFromFile(file);
  if (!trace_timestamp_) {
    PERFETTO_ELOG("Failed to read Tracealyzer trace timestamp data.");
    return false;
  }

  trace_entry_table_ = TraceEntryTable::ReadFromFile(file);
  if (!trace_entry_table_) {
    PERFETTO_ELOG("Failed to read Tracealyzer trace entry table.");
    return false;
  }

  PERFETTO_ILOG(
      "Trace header version: 0x%x, platform: 0x%x, "
      "platform config: %s, num cores: %u",
      trace_header_->Version(),
      static_cast<uint16_t>(trace_header_->Platform()),
      trace_header_->PlatformConfig(), trace_header_->NumCores());
  PERFETTO_ILOG(
      "Trace timestamp type: 0x%x, period: %u, frequency %u, "
      "OS tick Hz: %u, latest timestamp: %u, OS tick count: %u",
      trace_timestamp_->Type(), trace_timestamp_->Period(),
      trace_timestamp_->Frequency(), trace_timestamp_->OsTickHz(),
      trace_timestamp_->LatestTimestamp(), trace_timestamp_->OsTickCount());

  for (const auto& entry : trace_entry_table_->Entries()) {
    PERFETTO_ILOG("Trace entry: address: 0x%08x, symbol: %s", entry.pvAddress,
                  entry.szSymbol.c_str());
  }

  return true;
}

bool TracealyzerDataSource::ReadTraceEvent(base::ScopedFile& file,
                                           size_t& event_count) {
  std::unique_ptr<tracealyzer::TraceEvent> trace_event =
      tracealyzer::TraceEvent::ReadFromFile(file);

  while (trace_event) {
    event_count++;
    // Process the trace event.
    PERFETTO_DLOG("Read trace event: %s, count: %u, timestamp: %u",
                  GetEventName(trace_event->Event()), trace_event->EventCount(),
                  trace_event->Timestamp());

    if (!ProcessEvent(*trace_event)) {
      PERFETTO_ELOG("Failed to process trace event.");
    }

    trace_event = tracealyzer::TraceEvent::ReadFromFile(file);
  }

  trace_object_manager_.Flush();

  return true;
}

uint64_t TracealyzerDataSource::ConvertTimestampToNs(
    tracealyzer::TraceUnsignedBaseType_t ts) const {
  return trace_timestamp_->ConvertTimestampToNs(ts);
}

uint64_t TracealyzerDataSource::GenUuidFromPid(int32_t pid) {
  return std::hash<uint64_t>()(static_cast<uint64_t>(pid) << 32);
}

uint64_t TracealyzerDataSource::GenUuidFromTid(int32_t tid) {
  return std::hash<uint64_t>()(static_cast<uint64_t>(tid));
}

template <PsfEventCode EventCode>
bool TracealyzerDataSource::ProcessTraceEvent(const TraceEvent& event) {
  (void)event;
  // This function should be specialized for each event code.
  static_assert(EventCode == PsfEventCode::Unknown,
                "ConvertTraceEvent must be specialized for each event code.");
  return false;
}

template <>
bool TracealyzerDataSource::ProcessTraceEvent<PsfEventCode::TraceStart>(
    const TraceEvent& event) {
  auto packet = writer_->NewTracePacket();
  packet->set_timestamp(ConvertTimestampToNs(event.Timestamp()));
  auto desc = packet->set_track_descriptor();
  desc->set_uuid(GenUuidFromPid(kProcessId));
  auto process = desc->set_process();
  process->set_pid(kProcessId);
  process->set_process_name(kProcessName);
  return true;
}

template <>
bool TracealyzerDataSource::ProcessTraceEvent<PsfEventCode::ThreadInit>(
    const TraceEvent& event) {
  auto thread = Thread::FromEvent<Thread>(event, writer_);
  if (thread) {
    trace_object_manager_.AddObject(std::move(thread));
    return true;
  }
  PERFETTO_ELOG("Failed to create thread object from event.");
  return false;
}

template <>
bool TracealyzerDataSource::ProcessTraceEvent<PsfEventCode::ObjName>(
    const TraceEvent& event) {
  auto obj = trace_object_manager_.GetObject<TraceObject>(event.Args()[0]);
  obj->SetObjectName(reinterpret_cast<const char*>(&event.Args()[1]));
  return true;
}

template <>
bool TracealyzerDataSource::ProcessTraceEvent<PsfEventCode::TaskReady>(
    const TraceEvent& event) {
  auto obj = trace_object_manager_.GetObject<Thread>(event.Args()[0]);
  obj->ThreadReady(ConvertTimestampToNs(event.Timestamp()));
  return true;
}

template <>
bool TracealyzerDataSource::ProcessTraceEvent<PsfEventCode::TaskActivate>(
    const TraceEvent& event) {
  auto obj = trace_object_manager_.GetObject<Thread>(event.Args()[0]);
  trace_object_manager_.ThreadActivate(obj,
                                       ConvertTimestampToNs(event.Timestamp()));
  return true;
}

bool TracealyzerDataSource::ProcessEvent(
    const tracealyzer::TraceEvent& trace_event) {
  // Process the trace event and write it to the trace writer.
  switch (trace_event.Event()) {
    case PsfEventCode::TraceStart:
      ProcessTraceEvent<PsfEventCode::TraceStart>(trace_event);
      break;
    case PsfEventCode::ThreadInit:
      ProcessTraceEvent<PsfEventCode::ThreadInit>(trace_event);
      break;
    case PsfEventCode::ObjName:
      ProcessTraceEvent<PsfEventCode::ObjName>(trace_event);
      break;
    case PsfEventCode::TaskReady:
      ProcessTraceEvent<PsfEventCode::TaskReady>(trace_event);
      break;
    case PsfEventCode::TaskActivate:
      ProcessTraceEvent<PsfEventCode::TaskActivate>(trace_event);
      break;
    default: {
      // Handle other event types.
      break;
    }
  }

  return true;
}

void TracealyzerDataSource::Start() {
  if (!trace_file_) {
    return;
  }

  if (!ReadTraceHeader(trace_file_)) {
    return;
  }

  size_t event_count = 0;
  if (!ReadTraceEvent(trace_file_, event_count)) {
    PERFETTO_ELOG("Failed to read trace events from file.");
    return;
  }
  PERFETTO_ILOG("Total trace events read: %zu", event_count);
}

void TracealyzerDataSource::Flush(FlushRequestID,
                                  std::function<void()> callback) {
  writer_->Flush(callback);
}
}  // namespace perfetto

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
