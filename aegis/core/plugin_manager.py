"""مدير المكونات الإضافية — Plugin Manager.

يكتشف ويحمّل تلقائياً أي كلاس يرث من BasePlugin داخل الحزمة aegis.plugins،
يسجّله على ناقل الأحداث حسب مواضيعه، دون لمس الكود الأساسي أبداً.
"""

import importlib
import inspect
import logging
import pkgutil
from abc import ABC, abstractmethod
from collections.abc import Iterable
from pathlib import Path

from aegis.core.event_bus import Event, EventBus
from aegis.core.plugin_registry import PluginMetadata, PluginRegistry

logger = logging.getLogger("aegis.plugin_manager")


class BasePlugin(ABC):
    """القالب الإلزامي لكل مكوّن إضافي (أداة خارجية أو محرك داخلي).

    اشتق من هذا الكلاس، عرّف name/version/topics ونفّذ handle_event.
    """

    name: str = "base_plugin"
    version: str = "0.1.0"
    topics: tuple = ()

    def __init__(self, event_bus: EventBus) -> None:
        self.event_bus = event_bus

    @abstractmethod
    async def handle_event(self, event: Event) -> None:
        """معالجة الأحداث الواردة من المواضيع المسجل عليها المكوّن."""

    def register(self) -> None:
        """اشتراك المكوّن على جميع مواضيعه المعلنة."""
        for topic in self.topics:
            self.event_bus.subscribe(topic, self.handle_event)


class PluginManager:
    """اكتشاف وتحميل وإدارة دورة حياة المكونات الإضافية."""

    def __init__(self, event_bus: EventBus, registry_path: str | Path | None = None) -> None:
        self.event_bus = event_bus
        self.plugins: dict[str, BasePlugin] = {}
        self.registry = PluginRegistry(registry_path)

    def load_package(self, package_name: str = "aegis.plugins") -> int:
        """تحميل جميع الإضافات من حزمة بايثون؛ يعيد عدد الإضافات المحمّلة.

        القاعدة: كلاس يرث BasePlugin ومعرّف داخل وحدة الإضافة نفسها فقط.
        """
        package = importlib.import_module(package_name)
        package_dir = Path(getattr(package, "__path__", [Path(package.__file__).parent])[0])

        loaded = 0
        for module_info in pkgutil.iter_modules([str(package_dir)]):
            module_name = f"{package_name}.{module_info.name}"
            try:
                module = importlib.import_module(module_name)
            except Exception:
                logger.exception("Failed to import plugin module '%s'", module_name)
                continue

            for _, obj in inspect.getmembers(module, inspect.isclass):
                if (
                    issubclass(obj, BasePlugin)
                    and obj is not BasePlugin
                    and obj.__module__ == module.__name__
                ):
                    try:
                        instance = obj(self.event_bus)
                        instance.register()
                        self.plugins[obj.name] = instance
                        loaded += 1
                        logger.info("Plugin loaded: %s v%s", obj.name, obj.version)
                    except Exception:
                        logger.exception("Failed to instantiate plugin '%s'", obj.__name__)
        return loaded

    def get(self, name: str) -> BasePlugin | None:
        """إرجاع مكوّن محمّل بالاسم."""
        return self.plugins.get(name)

    def names(self) -> Iterable[str]:
        """أسماء جميع الإضافات المحمّلة."""
        return self.plugins.keys()

    def metadata(self, name: str) -> PluginMetadata | None:
        """قراءة metadata المسجلة دون تغيير دورة حياة الإضافة."""
        return self.registry.get(name)

    async def unload_all(self) -> None:
        """إلغاء اشتراك جميع الإضافات من الناقل."""
        for plugin in list(self.plugins.values()):
            for topic in plugin.topics:
                self.event_bus.unsubscribe(topic, plugin.handle_event)
        self.plugins.clear()
