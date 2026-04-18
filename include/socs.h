#ifndef _SOCS_H
#define _SOCS_H

#if CONFIG_SOC_EXYNOS7870
#define SOC_HEADER(x) <socs/exynos7870/x>
#elif CONFIG_SOC_EXYNOS7885
#define SOC_HEADER(x) <socs/exynos7885/x>
#else
#error "SOC_HEADER undefined for platform"
#endif

#endif /* _SOCS_H */
