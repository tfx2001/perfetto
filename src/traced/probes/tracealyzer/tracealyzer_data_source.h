#ifndef SRC_TRACED_PROBES_TRACEALYZER_TRACEALYZER_DATA_SOURCE_H_
#define SRC_TRACED_PROBES_TRACEALYZER_TRACEALYZER_DATA_SOURCE_H_

#include "trace_event.h"

#include <sys/cdefs.h>
#include <memory>

#include "perfetto/ext/base/scoped_file.h"
#include "perfetto/ext/tracing/core/trace_writer.h"
#include "perfetto/tracing/core/data_source_config.h"
#include "protos/perfetto/trace/track_event/track_event.pbzero.h"
#include "src/traced/probes/probes_data_source.h"

namespace perfetto {

using TraceWriterPtr = std::shared_ptr<TraceWriter>;

namespace base {
class TaskRunner;
}

namespace tracealyzer {
/* Assuming this is a typedef for unsigned base type. */
using TraceUnsignedBaseType_t = uint32_t;

template <class T>
class FromFile {
 public:
  static std::unique_ptr<T> ReadFromFile(base::ScopedFile& file);
  virtual ~FromFile();

 protected:
  bool Read(base::ScopedFile& file);

 private:
  FromFile() = default;

  friend T;
};

template <typename T>
struct FromFileTraits {};

class TraceHeader : public FromFile<TraceHeader> {
 public:
  enum class TracePlatform : uint16_t {
    BareMetal = 0x1FF1,
    FreeRTOS = 0x1AA1,
    ThreadX = 0xEAAE,
    Zephyr = 0x9AA9,
  };

  ~TraceHeader() override;

  uint16_t Version() const { return inner_.uiVersion; }
  TracePlatform Platform() const { return inner_.uiPlatform; }
  const char* PlatformConfig() const { return inner_.platformCfg; }
  uint32_t NumCores() const { return inner_.uiNumCores; }

 protected:
  bool Read(base::ScopedFile& file);

 private:
  constexpr static uint32_t kTraceHeaderMagic = 0x50534600;

  struct [[gnu::packed]] RawHeader {
    uint32_t uiPSF;
    uint16_t uiVersion;
    TracePlatform uiPlatform;
    uint32_t uiOptions;
    uint32_t uiNumCores;
    uint32_t isrTailchainingThreshold;
    uint16_t uiPlatformCfgPatch;
    uint8_t uiPlatformCfgMinor;
    uint8_t uiPlatformCfgMajor;
    char platformCfg[8];
  };

  TraceHeader() = default;

  RawHeader inner_;

  friend class FromFile<TraceHeader>;
};

class TraceTimestampData : public FromFile<TraceTimestampData> {
 public:
  ~TraceTimestampData() override;

  uint32_t Type() const { return inner_.type; }
  uint32_t Period() const { return inner_.period; }
  TraceUnsignedBaseType_t Frequency() const { return inner_.frequency; }
  uint32_t OsTickHz() const { return inner_.osTickHz; }
  uint32_t LatestTimestamp() const { return inner_.latestTimestamp; }
  uint32_t OsTickCount() const { return inner_.osTickCount; }

  uint64_t ConvertTimestampToNs(TraceUnsignedBaseType_t ts) const {
    return static_cast<uint64_t>(ts) * 1000000000 / inner_.frequency;
  }

 private:
  struct [[gnu::packed]] RawTimestampData {
    uint32_t type;                     /**< Timer type (direction) */
    uint32_t period;                   /**< Timer Period */
    TraceUnsignedBaseType_t frequency; /**< Timer Frequency */
    uint32_t wraparounds;              /**< Nr of timer wraparounds */
    uint32_t osTickHz;                 /**< RTOS tick frequency */
    uint32_t latestTimestamp;          /**< Latest timestamp */
    uint32_t osTickCount;              /**< RTOS tick count */
  };

  TraceTimestampData() = default;

  RawTimestampData inner_;

  friend class FromFile<TraceTimestampData>;
  friend struct FromFileTraits<TraceTimestampData>;
};

class TraceEntryTable : public FromFile<TraceEntryTable> {
 public:
  struct TraceEntry {
    TraceUnsignedBaseType_t pvAddress;
    std::vector<TraceUnsignedBaseType_t> xStates;
    uint32_t uiOptions;
    std::string szSymbol;
  };

  ~TraceEntryTable() override;

  const std::vector<TraceEntry>& Entries() const { return axEntries; }

 protected:
  bool Read(base::ScopedFile& file);

 private:
  TraceEntryTable() = default;

  TraceUnsignedBaseType_t uxSlots;
  TraceUnsignedBaseType_t uxEntrySymbolLength;
  TraceUnsignedBaseType_t uxEntryStateCount;
  std::vector<TraceEntry> axEntries;

  friend class FromFile<TraceEntryTable>;
};

class TraceEvent : public FromFile<TraceEvent> {
 public:
  ~TraceEvent() override;

  PsfEventCode Event() const { return event_; }
  uint16_t EventCount() const { return event_count_; }
  TraceUnsignedBaseType_t Timestamp() const { return timestamp_; }
  const std::vector<TraceUnsignedBaseType_t>& Args() const { return args_; }

 protected:
  bool Read(base::ScopedFile& file);

 private:
  TraceEvent() = default;

  PsfEventCode event_;
  uint16_t event_count_;               // Number of events since trace start.
  TraceUnsignedBaseType_t timestamp_;  // Timestamp of the event.
  std::vector<TraceUnsignedBaseType_t> args_;  // Arguments of the event.

  friend class FromFile<TraceEvent>;
};

class TraceObject {
 public:
  enum class Type {
    Thread,
    Semaphore,
    Mutex,
    EventGroup,
    Queue,
  };

  using TrackEventType =
      perfetto::protos::pbzero::perfetto_pbzero_enum_TrackEvent::Type;

  virtual ~TraceObject();
  TraceObject(const TraceObject&) = default;
  TraceObject(TraceObject&&) = delete;

  template <typename T>
  static std::unique_ptr<T> FromEvent(const TraceEvent& event,
                                      TraceWriterPtr writer);

  TraceUnsignedBaseType_t GetHandle() const { return handle_; }
  void SetObjectName(const std::string& name) { name_ = name; }
  const std::string& GetObjectName() const { return name_; }
  Type GetType() const { return type_; }
  virtual void Flush() = 0;

 protected:
  TraceObject(TraceUnsignedBaseType_t handle,
              const std::string& name,
              Type type,
              TraceWriterPtr writer);
  void AddTrackEvent(uint64_t timestamp,
                     TrackEventType type,
                     uint64_t event_track_uuid,
                     std::optional<std::string> name = std::nullopt);

  TraceWriterPtr writer_;

 private:
  TraceUnsignedBaseType_t handle_;
  std::string name_;
  Type type_;
};

class Thread : public TraceObject {
 public:
  ~Thread() override;
  Thread(const Thread&) = default;
  Thread(Thread&&) = delete;

  int32_t GetThreadId() const { return tid_; }
  void ThreadReady(uint64_t timestamp);
  void ThreadSchedIn(uint64_t timestamp);
  void ThreadSchedOut(uint64_t timestamp);

  void Flush() override;

 private:
  Thread(TraceUnsignedBaseType_t handle,
         const std::string& name,
         uint32_t stack_size,
         uint32_t prio,
         TraceWriterPtr writer);

  int32_t tid_;
  uint32_t stack_size_;
  uint32_t prio_;

  friend TraceObject;
};

class ThreadIdAllocator {
 public:
  static ThreadIdAllocator& Instance() {
    static ThreadIdAllocator instance;
    return instance;
  }

  int32_t NextThreadId();

 private:
  ThreadIdAllocator();
  ThreadIdAllocator(const ThreadIdAllocator&) = delete;
  ThreadIdAllocator& operator=(const ThreadIdAllocator&) = delete;

  int32_t next_tid_ = 0;
};

class TraceObjectManager {
 public:
  explicit TraceObjectManager(TraceWriterPtr writer);

  template <typename T>
  std::shared_ptr<T> GetObject(TraceUnsignedBaseType_t handle);
  void AddObject(std::unique_ptr<TraceObject> object);
  void ThreadActivate(std::shared_ptr<Thread> thread, uint64_t timestamp);
  void Flush();

 private:
  std::unordered_map<TraceUnsignedBaseType_t, std::shared_ptr<TraceObject>>
      objects_;
  TraceWriterPtr writer_;
  std::shared_ptr<Thread> current_thread_;
};
}  // namespace tracealyzer

class TracealyzerDataSource : public ProbesDataSource {
 public:
  static const ProbesDataSource::Descriptor descriptor;

  TracealyzerDataSource(base::TaskRunner* task_runner,
                        const DataSourceConfig& ds_config,
                        TracingSessionID session_id,
                        std::unique_ptr<TraceWriter> writer);

  // ProbesDataSource implementation.
  void Start() override;
  void Flush(FlushRequestID, std::function<void()> callback) override;

  static uint64_t GenUuidFromPid(int32_t pid);
  static uint64_t GenUuidFromTid(int32_t tid);

  // Virtual for testing.
  // virtual std::string ReadFile(std::string path);

 private:
  bool ReadTraceHeader(base::ScopedFile& file);
  bool ReadTraceEvent(base::ScopedFile& file, size_t& event_count);
  bool ProcessEvent(const tracealyzer::TraceEvent& trace_event);
  uint64_t ConvertTimestampToNs(tracealyzer::TraceUnsignedBaseType_t ts) const;

  template <tracealyzer::PsfEventCode EventCode>
  bool ProcessTraceEvent(const tracealyzer::TraceEvent& event);

  [[maybe_unused]] base::TaskRunner* const task_runner_;
  TraceWriterPtr writer_;
  base::ScopedFile trace_file_;

  std::unique_ptr<tracealyzer::TraceHeader> trace_header_ = nullptr;
  std::unique_ptr<tracealyzer::TraceTimestampData> trace_timestamp_ = nullptr;
  std::unique_ptr<tracealyzer::TraceEntryTable> trace_entry_table_ = nullptr;

  tracealyzer::TraceObjectManager trace_object_manager_;
};

}  // namespace perfetto

#endif  // SRC_TRACED_PROBES_TRACEALYZER_TRACEALYZER_DATA_SOURCE_H_
