"""TUI for CloudShell VPN using Textual."""

from textual.app import App, ComposeResult
from textual.widgets import Static, ListItem, ListView, RichLog
from textual.containers import Container
from textual.binding import Binding
from textual import work
from typing import Optional, Callable
from pathlib import Path
import asyncio
import json
import time

# Config file for history
from .common import DATA_DIR
CONFIG_DIR = DATA_DIR
HISTORY_FILE = CONFIG_DIR / "history.json"
MAX_HISTORY = 5


def load_history() -> list[str]:
    """Load recently used regions from history file."""
    try:
        if HISTORY_FILE.exists():
            data = json.loads(HISTORY_FILE.read_text())
            return data.get("recent_regions", [])[:MAX_HISTORY]
    except Exception:
        pass
    return []


def save_history(regions: list[str]) -> None:
    """Save recently used regions to history file."""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        data = {"recent_regions": regions[:MAX_HISTORY]}
        HISTORY_FILE.write_text(json.dumps(data, indent=2))
    except Exception:
        pass


def add_to_history(region: str) -> None:
    """Add a region to the history (most recent first)."""
    history = load_history()
    # Remove if already present
    if region in history:
        history.remove(region)
    # Add at the beginning
    history.insert(0, region)
    save_history(history[:MAX_HISTORY])


# Region metadata (display names and grouping)
# This is just for display - actual availability comes from AWS API
REGION_INFO = {
    # North America
    "us-east-1": ("N. Virginia", "🌎 North America"),
    "us-east-2": ("Ohio", "🌎 North America"),
    "us-west-1": ("N. California", "🌎 North America"),
    "us-west-2": ("Oregon", "🌎 North America"),
    "ca-central-1": ("Montreal", "🌎 North America"),
    "ca-west-1": ("Calgary", "🌎 North America"),
    # South America
    "sa-east-1": ("São Paulo", "🌎 South America"),
    # Europe
    "eu-west-1": ("Ireland", "🌍 Europe"),
    "eu-west-2": ("London", "🌍 Europe"),
    "eu-west-3": ("Paris", "🌍 Europe"),
    "eu-central-1": ("Frankfurt", "🌍 Europe"),
    "eu-central-2": ("Zurich", "🌍 Europe"),
    "eu-north-1": ("Stockholm", "🌍 Europe"),
    "eu-south-1": ("Milan", "🌍 Europe"),
    "eu-south-2": ("Spain", "🌍 Europe"),
    # Middle East
    "me-south-1": ("Bahrain", "🌍 Middle East"),
    "me-central-1": ("UAE", "🌍 Middle East"),
    "il-central-1": ("Tel Aviv", "🌍 Middle East"),
    # Africa
    "af-south-1": ("Cape Town", "🌍 Africa"),
    # Asia Pacific
    "ap-south-1": ("Mumbai", "🌏 Asia Pacific"),
    "ap-south-2": ("Hyderabad", "🌏 Asia Pacific"),
    "ap-southeast-1": ("Singapore", "🌏 Asia Pacific"),
    "ap-southeast-2": ("Sydney", "🌏 Asia Pacific"),
    "ap-southeast-3": ("Jakarta", "🌏 Asia Pacific"),
    "ap-southeast-4": ("Melbourne", "🌏 Asia Pacific"),
    "ap-southeast-5": ("Malaysia", "🌏 Asia Pacific"),
    "ap-southeast-7": ("Thailand", "🌏 Asia Pacific"),
    "ap-northeast-1": ("Tokyo", "🌏 Asia Pacific"),
    "ap-northeast-2": ("Seoul", "🌏 Asia Pacific"),
    "ap-northeast-3": ("Osaka", "🌏 Asia Pacific"),
    "ap-east-1": ("Hong Kong", "🌏 Asia Pacific"),
}

# Group order for display
GROUP_ORDER = [
    "🌎 North America",
    "🌎 South America",
    "🌍 Europe",
    "🌍 Middle East",
    "🌍 Africa",
    "🌏 Asia Pacific",
]


def get_region_name(code: str) -> str:
    """Get display name for a region code."""
    if code in REGION_INFO:
        return REGION_INFO[code][0]
    return code


def get_region_group(code: str) -> str:
    """Get group for a region code."""
    if code in REGION_INFO:
        return REGION_INFO[code][1]
    # Unknown regions go to a generic group based on prefix
    if code.startswith("us-") or code.startswith("ca-"):
        return "🌎 North America"
    elif code.startswith("sa-"):
        return "🌎 South America"
    elif code.startswith("eu-"):
        return "🌍 Europe"
    elif code.startswith("me-") or code.startswith("il-"):
        return "🌍 Middle East"
    elif code.startswith("af-"):
        return "🌍 Africa"
    elif code.startswith("ap-"):
        return "🌏 Asia Pacific"
    return "🌐 Other"


class RegionItem(ListItem):
    """A region list item."""
    
    def __init__(self, code: str) -> None:
        super().__init__()
        self.region_code = code
        self.region_name = get_region_name(code)
    
    def compose(self) -> ComposeResult:
        yield Static(f"  {self.region_code:<20} {self.region_name}")


class GroupHeader(ListItem):
    """A group header (not selectable)."""
    
    def __init__(self, group: str) -> None:
        super().__init__()
        self.group = group
        self.disabled = True
    
    def compose(self) -> ComposeResult:
        yield Static(f"{self.group}", markup=False, classes="group-header-text")


class StatusPanel(Static):
    """Status display panel."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._status = "Disconnected"
        self._region = ""
        self._duration = 0
        self._bytes_in = 0
        self._bytes_out = 0
        self._latency_ms = 0
    
    def set_status(self, status: str, region: str = ""):
        self._status = status
        self._region = region
        self._update_display()
    
    def set_stats(self, duration: int, bytes_in: int, bytes_out: int, latency_ms: int = 0):
        self._duration = duration
        self._bytes_in = bytes_in
        self._bytes_out = bytes_out
        self._latency_ms = latency_ms
        self._update_display()
    
    def _update_display(self):
        if self._status == "Disconnected":
            self.update("[dim]● Disconnected[/]")
        elif self._status == "Connecting":
            self.update(f"[yellow]◐ Connecting to {self._region}...[/]")
        elif self._status == "Reconnecting":
            self.update(f"[yellow]◐ Reconnecting to {self._region}...[/]")
        elif self._status == "Connected":
            mins, secs = divmod(self._duration, 60)
            hours, mins = divmod(mins, 60)
            duration_str = f"{hours:02d}:{mins:02d}:{secs:02d}"
            region_name = get_region_name(self._region)
            
            # Latency color
            if self._latency_ms == 0:
                latency_str = "[dim]--[/]"
            elif self._latency_ms < 100:
                latency_str = f"[green]{self._latency_ms}ms[/]"
            elif self._latency_ms < 200:
                latency_str = f"[yellow]{self._latency_ms}ms[/]"
            else:
                latency_str = f"[red]{self._latency_ms}ms[/]"
            
            def fmt_bytes(b):
                if b < 1024:
                    return f"{b} B"
                elif b < 1024 * 1024:
                    return f"{b/1024:.1f} KB"
                else:
                    return f"{b/1024/1024:.1f} MB"
            
            self.update(
                f"[green]● Connected[/] to [bold]{self._region}[/] ({region_name})\n"
                f"⏱ {duration_str}  │  📶 {latency_str}  │  ↓ {fmt_bytes(self._bytes_in)}  │  ↑ {fmt_bytes(self._bytes_out)}"
            )
        else:
            self.update(f"[red]● {self._status}[/]")


class CloudShellVPN(App):
    """CloudShell VPN TUI with full connection management."""
    
    CSS = """
    Screen {
        background: $surface;
    }
    
    #title {
        dock: top;
        height: 3;
        content-align: center middle;
        background: $primary;
        text-style: bold;
    }
    
    #main {
        height: 1fr;
    }
    
    #region-list {
        width: 100%;
        height: 1fr;
        border: solid $primary;
    }
    
    ListView > ListItem.--highlight {
        background: $accent;
    }
    
    RegionItem {
        height: 1;
    }
    
    GroupHeader {
        height: 1;
    }
    
    .group-header-text {
        text-style: bold;
        color: cyan;
    }
    
    #status-panel {
        dock: top;
        height: 4;
        background: $panel;
        border-bottom: solid $primary;
    }
    
    #log-panel {
        height: 1fr;
        border: solid $primary;
        padding: 1;
    }
    
    Log {
        height: 100%;
    }
    
    #footer {
        dock: bottom;
        height: 1;
        background: $panel;
        content-align: center middle;
    }
    
    .hidden {
        display: none;
    }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("escape", "back", "Back"),
        Binding("enter", "select", "Connect/Retry"),
        Binding("d", "disconnect", "Disconnect"),
        Binding("r", "retry", "Retry"),
    ]
    
    def __init__(self, available_regions: list[str], vpn_runner: Optional[Callable] = None) -> None:
        super().__init__()
        self.available_regions = available_regions
        self.current_view = "picker"
        self.selected_region: Optional[str] = None
        self.vpn_start_time: float = 0
        self.vpn_runner = vpn_runner
        self._stop_vpn = asyncio.Event()
    
    def compose(self) -> ComposeResult:
        yield Static("☁️  CloudShell VPN", id="title")
        
        with Container(id="main"):
            yield StatusPanel(id="status-panel", classes="hidden")
            
            # Build region list grouped by geography
            items = []
            
            # Add recent regions first
            history = load_history()
            recent_available = [r for r in history if r in self.available_regions]
            if recent_available:
                items.append(GroupHeader("⭐ Recent"))
                for code in recent_available:
                    items.append(RegionItem(code))
            
            # Group remaining regions
            regions_by_group = {}
            for code in self.available_regions:
                group = get_region_group(code)
                if group not in regions_by_group:
                    regions_by_group[group] = []
                regions_by_group[group].append(code)
            
            # Sort groups and regions
            for group in GROUP_ORDER:
                if group in regions_by_group:
                    items.append(GroupHeader(group))
                    for code in sorted(regions_by_group[group]):
                        items.append(RegionItem(code))
            
            # Any remaining groups not in ORDER
            for group in sorted(regions_by_group.keys()):
                if group not in GROUP_ORDER:
                    items.append(GroupHeader(group))
                    for code in sorted(regions_by_group[group]):
                        items.append(RegionItem(code))
            
            yield ListView(*items, id="region-list")
            yield RichLog(id="log-panel", classes="hidden", markup=True)
        
        yield Static("↑↓ Navigate • Enter Connect • q Quit", id="footer")
    
    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, RegionItem):
            self.selected_region = event.item.region_code
            self.start_vpn()
    
    def action_select(self) -> None:
        if self.current_view == "picker":
            list_view = self.query_one("#region-list", ListView)
            if list_view.highlighted_child and isinstance(list_view.highlighted_child, RegionItem):
                self.selected_region = list_view.highlighted_child.region_code
                self.start_vpn()
        elif self.current_view in ("connecting", "connected"):
            # Allow retry with Enter
            self.action_retry()
    
    def action_retry(self) -> None:
        """Retry connection to the same region."""
        if self.current_view in ("connecting", "connected") and self.selected_region:
            self._stop_vpn.set()  # Stop current attempt
            self.start_vpn()  # Restart
    
    def action_back(self) -> None:
        if self.current_view in ("connecting", "connected"):
            self.stop_vpn()
    
    def action_disconnect(self) -> None:
        if self.current_view == "connected":
            self.stop_vpn()
    
    def action_quit(self) -> None:
        if self.current_view in ("connecting", "connected"):
            self.stop_vpn()
        self.exit()
    
    def start_vpn(self) -> None:
        self.current_view = "connecting"
        self._stop_vpn.clear()
        
        # Add to history
        add_to_history(self.selected_region)
        
        self.query_one("#region-list").add_class("hidden")
        self.query_one("#status-panel").remove_class("hidden")
        self.query_one("#log-panel").remove_class("hidden")
        self.query_one("#footer").update("Esc Cancel • q Quit")
        
        status = self.query_one("#status-panel", StatusPanel)
        status.set_status("Connecting", self.selected_region)
        
        log = self.query_one("#log-panel", RichLog)
        log.clear()
        
        self._run_vpn()
    
    @work(exclusive=True, thread=True)
    def _run_vpn(self) -> None:
        if self.vpn_runner:
            max_retries = 3
            retry_count = 0
            
            while retry_count < max_retries and not self._stop_vpn.is_set():
                try:
                    self.vpn_runner(
                        region=self.selected_region,
                        log_callback=self._log_message,
                        status_callback=self._update_status,
                        stop_event=self._stop_vpn,
                    )
                    break  # Normal exit
                except ConnectionError as e:
                    # Auto-reconnect on connection lost
                    retry_count += 1
                    if retry_count < max_retries and not self._stop_vpn.is_set():
                        self.call_from_thread(self._log_message, f"[yellow]Reconnecting ({retry_count}/{max_retries})...[/]")
                        self.call_from_thread(self._set_reconnecting)
                        time.sleep(2)  # Brief pause before retry
                    else:
                        self.call_from_thread(self._log_message, f"[red]Connection lost after {max_retries} retries[/]")
                        self.call_from_thread(self._set_error, str(e))
                except Exception as e:
                    self.call_from_thread(self._log_message, f"[red]Error: {e}[/]")
                    self.call_from_thread(self._set_error, str(e))
                    break
            
            # When VPN stops, update footer to allow retry
            self.call_from_thread(self._on_vpn_stopped)
    
    def _set_reconnecting(self) -> None:
        """Set status to reconnecting."""
        try:
            status = self.query_one("#status-panel", StatusPanel)
            status.set_status("Reconnecting", self.selected_region)
        except Exception:
            pass
    
    def _on_vpn_stopped(self) -> None:
        """Called when VPN runner exits (success or error)."""
        if self.current_view in ("connecting", "connected"):
            self.query_one("#footer").update("Enter Retry • Esc Back • q Quit")
    
    def _log_message(self, msg: str) -> None:
        """Thread-safe log message."""
        self.call_from_thread(self._do_log, msg)
    
    def _do_log(self, msg: str) -> None:
        try:
            log = self.query_one("#log-panel", RichLog)
            log.write(msg)
        except Exception:
            pass
    
    def _update_status(self, connected: bool = False, bytes_in: int = 0, bytes_out: int = 0, latency_ms: int = 0) -> None:
        """Thread-safe status update."""
        self.call_from_thread(self._do_update_status, connected, bytes_in, bytes_out, latency_ms)
    
    def _do_update_status(self, connected: bool, bytes_in: int, bytes_out: int, latency_ms: int) -> None:
        try:
            status = self.query_one("#status-panel", StatusPanel)
            if connected and self.current_view != "connected":
                self.current_view = "connected"
                self.vpn_start_time = time.time()
                status.set_status("Connected", self.selected_region)
                self.query_one("#footer").update("d Disconnect • q Quit")
                self.set_interval(1, self._update_timer)
            duration = int(time.time() - self.vpn_start_time) if self.current_view == "connected" else 0
            status.set_stats(duration, bytes_in, bytes_out, latency_ms)
        except Exception:
            pass
    
    def _set_error(self, error: str) -> None:
        try:
            status = self.query_one("#status-panel", StatusPanel)
            status.set_status(f"Error: {error}")
        except Exception:
            pass
    
    def _update_timer(self) -> None:
        if self.current_view == "connected":
            try:
                status = self.query_one("#status-panel", StatusPanel)
                duration = int(time.time() - self.vpn_start_time)
                status.set_stats(duration, status._bytes_in, status._bytes_out, status._latency_ms)
            except Exception:
                pass
    
    def stop_vpn(self) -> None:
        self._stop_vpn.set()
        
        self.current_view = "picker"
        self.query_one("#region-list").remove_class("hidden")
        self.query_one("#status-panel").add_class("hidden")
        self.query_one("#log-panel").add_class("hidden")
        self.query_one("#footer").update("↑↓ Navigate • Enter Connect • q Quit")
        
        status = self.query_one("#status-panel", StatusPanel)
        status.set_status("Disconnected")
        status.set_stats(0, 0, 0)


class RegionPickerSimple(App):
    """Simple region picker for standalone use."""
    
    CSS = """
    Screen { background: $surface; }
    #title { dock: top; height: 3; content-align: center middle; background: $primary; text-style: bold; }
    ListView { height: 1fr; border: solid $primary; }
    ListView > ListItem.--highlight { background: $accent; }
    RegionItem { height: 1; }
    GroupHeader { height: 1; }
    #footer { dock: bottom; height: 1; background: $panel; content-align: center middle; }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("escape", "quit", "Quit"),
        Binding("enter", "select", "Connect"),
    ]
    
    def __init__(self, available_regions: list[str]) -> None:
        super().__init__()
        self.available_regions = available_regions
        self.selected_region: Optional[str] = None
    
    def compose(self) -> ComposeResult:
        yield Static("☁️  CloudShell VPN - Select Region", id="title")
        
        items = []
        regions_by_group = {}
        for code in self.available_regions:
            group = get_region_group(code)
            if group not in regions_by_group:
                regions_by_group[group] = []
            regions_by_group[group].append(code)
        
        for group in GROUP_ORDER:
            if group in regions_by_group:
                items.append(GroupHeader(group))
                for code in sorted(regions_by_group[group]):
                    items.append(RegionItem(code))
        
        for group in sorted(regions_by_group.keys()):
            if group not in GROUP_ORDER:
                items.append(GroupHeader(group))
                for code in sorted(regions_by_group[group]):
                    items.append(RegionItem(code))
        
        yield ListView(*items)
        yield Static("↑↓ Navigate • Enter Connect • q Quit", id="footer")
    
    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if isinstance(event.item, RegionItem):
            self.selected_region = event.item.region_code
            self.exit()
    
    def action_select(self) -> None:
        list_view = self.query_one(ListView)
        if list_view.highlighted_child and isinstance(list_view.highlighted_child, RegionItem):
            self.selected_region = list_view.highlighted_child.region_code
            self.exit()
    
    def action_quit(self) -> None:
        self.exit()


def select_region(available_regions: list[str]) -> Optional[str]:
    """Show region picker and return selected region."""
    app = RegionPickerSimple(available_regions)
    app.run()
    return app.selected_region


def run_vpn_tui(available_regions: list[str], vpn_runner: Callable) -> None:
    """Run the full VPN TUI."""
    app = CloudShellVPN(available_regions, vpn_runner)
    app.run()
