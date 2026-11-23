#include <cstdint>
#include <atomic>

namespace runtime {
struct RenderConfig {
    uint32_t target_fps = 144;
    float smooth_factor = 1.45f;
};
static std::atomic<bool> g_running{true};
}  // namespace runtime

int main() {
    while (runtime::g_running.load()) {
        runtime::g_running.store(false);
    }
    return 0;
}
