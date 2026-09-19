import sys
import os
import json
import unicodedata
import urllib.parse
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QListWidget, QListWidgetItem,
                             QStackedWidget, QFileDialog, QMessageBox, QInputDialog, QTableWidget,
                             QTableWidgetItem, QHeaderView, QProgressBar, QTextEdit, QSlider,
                             QStyle, QCheckBox, QStyledItemDelegate, QStyleOptionViewItem)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QUrl, QPoint, QPointF, QSize, QRectF, QTimer
from PyQt6.QtGui import QFont, QIcon, QColor, QPixmap, QPainter, QImage, QShortcut, QKeySequence, QPainterPath, QFontDatabase
try:
    from PyQt6.QtMultimedia import QMediaPlayer, QAudioOutput
    from PyQt6.QtMultimediaWidgets import QVideoWidget
except ImportError:
    QMediaPlayer = None
    QAudioOutput = None
    QVideoWidget = None
try:
    from PyQt6.QtWebEngineWidgets import QWebEngineView
except ImportError:
    QWebEngineView = None

from mediahub_core import MHClient
from mediahub_proxy import MHProxy
import Opsec

try:
    import keyring
    HAS_KEYRING = True
except ImportError:
    HAS_KEYRING = False

KR_SVC = "mediahub"
KR_ACC = "session"

class RowSelectionDelegate(QStyledItemDelegate):
    def paint(self, painter, option, index):
        if option.state & QStyle.StateFlag.State_Selected:
            painter.save()
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            
            color = QColor(255, 255, 255, 38)
            painter.setBrush(color)
            painter.setPen(Qt.PenStyle.NoPen)
            
            rect = QRectF(option.rect)
            bg_rect = rect.adjusted(0, 2, 0, -2)
            path = QPainterPath()
            radius = 4.0
            
            col = index.column()
            col_count = index.model().columnCount()
            
            if col_count == 1:
                path.addRoundedRect(bg_rect, radius, radius)
            elif col == 0:
                path.moveTo(bg_rect.topRight())
                path.lineTo(bg_rect.topLeft() + QPointF(radius, 0))
                path.arcTo(bg_rect.left(), bg_rect.top(), radius*2, radius*2, 90, 90)
                path.lineTo(bg_rect.bottomLeft() - QPointF(0, radius))
                path.arcTo(bg_rect.left(), bg_rect.bottom() - radius*2, radius*2, radius*2, 180, 90)
                path.lineTo(bg_rect.bottomRight())
                path.closeSubpath()
            elif col == col_count - 1:
                path.moveTo(bg_rect.topLeft())
                path.lineTo(bg_rect.topRight() - QPointF(radius, 0))
                path.arcTo(bg_rect.right() - radius*2, bg_rect.top(), radius*2, radius*2, 90, -90)
                path.lineTo(bg_rect.bottomRight() - QPointF(0, radius))
                path.arcTo(bg_rect.right() - radius*2, bg_rect.bottom() - radius*2, radius*2, radius*2, 0, -90)
                path.lineTo(bg_rect.bottomLeft())
                path.closeSubpath()
            else:
                path.addRect(bg_rect)
                
            painter.drawPath(path)
            painter.restore()
            
            opt = QStyleOptionViewItem(option)
            opt.state &= ~QStyle.StateFlag.State_Selected
            super().paint(painter, opt, index)
        else:
            super().paint(painter, option, index)

# --- Utility Widgets ---

class SortItem(QTableWidgetItem):
    def __lt__(self, other):
        d1 = self.data(Qt.ItemDataRole.UserRole)
        d2 = other.data(Qt.ItemDataRole.UserRole)
        if d1 is not None and d2 is not None:
            return d1 < d2
        return super().__lt__(other)


class ClickSldr(QSlider):
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            val = QStyle.sliderValueFromPosition(
                self.minimum(), self.maximum(),
                int(event.position().x()), self.width())
            self.setValue(val)
            self.sliderMoved.emit(val)
        super().mousePressEvent(event)


class ScaleLabel(QLabel):
    zoomChanged = pyqtSignal(float)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._pm = None
        self._sc = 1.0
        self._off = QPointF(0, 0)
        self._last = QPointF(0, 0)
        from PyQt6.QtWidgets import QSizePolicy
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    def setPixmap(self, pm):
        self._pm = pm
        self._sc = 1.0
        self._off = QPointF(0, 0)
        self.zoomChanged.emit(self.totalScale())
        self.update()

    def getFitScale(self):
        if not self._pm or self._pm.width() <= 0 or self._pm.height() <= 0:
            return 1.0
        w_ratio = self.width() / self._pm.width()
        h_ratio = self.height() / self._pm.height()
        return min(w_ratio, h_ratio)

    def totalScale(self):
        return self.getFitScale() * self._sc
    def _clampOff(self):
        if not self._pm:
            return
        img_w = self._pm.width() * self.totalScale()
        img_h = self._pm.height() * self.totalScale()
        cx = self.width() / 2.0
        cy = self.height() / 2.0
        
        max_x = max(0.0, (img_w / 2.0) - cx)
        max_y = max(0.0, (img_h / 2.0) - cy)
        
        x = max(-max_x, min(self._off.x(), max_x))
        y = max(-max_y, min(self._off.y(), max_y))
        self._off = QPointF(x, y)

    def event(self, ev):
        from PyQt6.QtCore import QEvent, Qt
        if ev.type() == QEvent.Type.NativeGesture:
            if ev.gestureType() == Qt.NativeGestureType.ZoomNativeGesture:
                if not self._pm:
                    return True
                
                step = 1.0 + ev.value()
                if step <= 0.01:
                    step = 0.01
                
                pos = ev.position()
                cx = self.width() / 2.0
                cy = self.height() / 2.0
                mouse_from_center = pos - QPointF(cx, cy)
                
                old_sc = self._sc
                new_sc = max(0.1, min(old_sc * step, 10.0))
                actual_step = new_sc / old_sc
                
                self._off = mouse_from_center - (mouse_from_center - self._off) * actual_step
                self._sc = new_sc
                self._clampOff()
                self.zoomChanged.emit(self.totalScale())
                self.update()
                return True
        return super().event(ev)

    def wheelEvent(self, ev):
        if not self._pm:
            return
        delta = ev.angleDelta().y()
        if delta == 0:
            return
        
        import math
        step = math.exp(delta * 0.0008)
        
        pos = ev.position()
        cx = self.width() / 2.0
        cy = self.height() / 2.0
        mouse_from_center = pos - QPointF(cx, cy)
        
        old_sc = self._sc
        new_sc = max(0.1, min(old_sc * step, 10.0))
        actual_step = new_sc / old_sc
        
        self._off = mouse_from_center - (mouse_from_center - self._off) * actual_step
        self._sc = new_sc
        self._clampOff()
        self.zoomChanged.emit(self.totalScale())
        self.update()

    def mousePressEvent(self, ev):
        if ev.button() == Qt.MouseButton.LeftButton:
            self._last = ev.position()

    def mouseMoveEvent(self, ev):
        if ev.buttons() & Qt.MouseButton.LeftButton:
            self._off += ev.position() - self._last
            self._last = ev.position()
            self._clampOff()
            self.update()

    def resizeEvent(self, ev):
        super().resizeEvent(ev)
        if self._pm:
            self._clampOff()
            self.zoomChanged.emit(self.totalScale())

    def paintEvent(self, ev):
        if not self._pm:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        
        fit_scale = self.getFitScale()
        total_scale = fit_scale * self._sc
        
        cx = self.width() / 2.0
        cy = self.height() / 2.0
        
        p.translate(cx + self._off.x(), cy + self._off.y())
        p.scale(total_scale, total_scale)
        
        px = -self._pm.width() / 2.0
        py = -self._pm.height() / 2.0
        
        p.drawPixmap(QPointF(px, py), self._pm)

    def zoomIn(self):
        if not self._pm:
            return
        self.zoomTo(self._sc * 1.2)

    def zoomOut(self):
        if not self._pm:
            return
        self.zoomTo(self._sc / 1.2)

    def zoomTo(self, target_sc):
        target_sc = max(0.1, min(target_sc, 10.0))
        self._off = self._off * (target_sc / self._sc)
        self._sc = target_sc
        self._clampOff()
        self.zoomChanged.emit(self.totalScale())
        self.update()

    def resetZoom(self):
        self._sc = 1.0
        self._off = QPointF(0, 0)
        self.zoomChanged.emit(self.totalScale())
        self.update()

    def originalSize(self):
        if not self._pm:
            return
        fit_scale = self.getFitScale()
        if fit_scale > 0:
            self.zoomTo(1.0 / fit_scale)
            self._off = QPointF(0, 0)
            self.update()


# --- Worker Threads ---

class WkBase(QThread):
    error = pyqtSignal(str)


class WkLogin(WkBase):
    success = pyqtSignal()

    def __init__(self, cli):
        super().__init__()
        self.cli = cli

    def run(self):
        try:
            self.cli.auth()
            self.success.emit()
        except Exception as e:
            self.error.emit(str(e))


class WkFlds(WkBase):
    success = pyqtSignal(dict)

    def __init__(self, cli):
        super().__init__()
        self.cli = cli

    def run(self):
        try:
            self.success.emit(self.cli.getFlds())
        except Exception as e:
            self.error.emit(str(e))


class WkFiles(WkBase):
    success = pyqtSignal(str, bytes, dict)

    def __init__(self, cli, name):
        super().__init__()
        self.cli = cli
        self.name = name

    def run(self):
        try:
            pid, key, files = self.cli.getFiles(self.name)
            self.success.emit(pid, key, files)
        except Exception as e:
            self.error.emit(str(e))


class WkUpload(WkBase):
    success = pyqtSignal()
    progress = pyqtSignal(int, int, float)

    def __init__(self, cli, fPid, fKey, flMap, paths):
        super().__init__()
        self.cli = cli
        self.fPid = fPid
        self.fKey = fKey
        self.flMap = flMap
        self.paths = paths

    def run(self):
        try:
            for fp in self.paths:
                self.cli.upFile(
                    self.fPid, self.fKey, self.flMap, fp,
                    progCb=lambda s, t, spd: self.progress.emit(s, t, spd))
            self.success.emit()
        except Exception as e:
            self.error.emit(str(e))


class WkDown(WkBase):
    success = pyqtSignal(str)

    def __init__(self, cli, fPid, flInfo, name, outDir):
        super().__init__()
        self.cli = cli
        self.fPid = fPid
        self.flInfo = flInfo
        self.name = name
        self.outDir = outDir

    def run(self):
        try:
            self.success.emit(self.cli.dnFile(self.fPid, self.flInfo, self.name, self.outDir))
        except Exception as e:
            self.error.emit(str(e))


class WkThumb(WkBase):
    success = pyqtSignal(str, bytes)  # fpid, raw image bytes

    def __init__(self, cli, fPid, fpid, fkBytes):
        super().__init__()
        self.cli = cli
        self.fPid = fPid
        self.fpid = fpid
        self.fkBytes = fkBytes

    def run(self):
        try:
            import requests
            import Bencrypt
            url = f"{self.cli.url}/api/media/{self.fPid}/{self.fpid}/thumb"
            res = requests.get(url, verify=self.cli.verify_ssl)
            if res.status_code == 200 and res.content:
                sm = Bencrypt.SymMaster("gcm1", self.fkBytes[:32])
                raw = sm.DeBin(res.content)
                if raw:
                    self.success.emit(self.fpid, raw)
        except Exception:
            pass


# --- Viewer Window ---

class Viewer(QMainWindow):
    def __init__(self, fileUrl, fileName, parent=None):
        super().__init__(parent)
        self.fileUrl = fileUrl
        self.setWindowTitle(f"MediaHub - {fileName}")
        self.resize(800, 600)
        self.setStyleSheet("""
            QMainWindow, #viewerCw { 
                background-color: #2C2C2E; 
                color: #FFFFFF; 
            }
            QWidget { font-family: 'Pretendard Variable', -apple-system, BlinkMacSystemFont, 'SF Pro Text', 'Segoe UI', sans-serif; font-size: 13px; }
            QLabel { color: #FFFFFF; }
            QTextEdit { 
                background-color: rgba(0, 0, 0, 0.4); 
                color: #FFFFFF; 
                border: 1px solid #3A3A3C; 
                border-radius: 12px; 
                padding: 10px; 
            }
            QPushButton { 
                background-color: rgba(255, 255, 255, 0.1); 
                color: #FFFFFF; 
                border: 1px solid #48484A; 
                border-radius: 8px; 
                padding: 6px 14px; 
                font-weight: 500; 
            }
            QPushButton:hover { background-color: rgba(255, 255, 255, 0.2); border-color: #5C5C5E; }
            QPushButton:pressed { background-color: rgba(255, 255, 255, 0.05); }
        """)

        self.cw = QWidget()
        self.cw.setObjectName("viewerCw")
        self.setCentralWidget(self.cw)
        self.lay = QVBoxLayout(self.cw)
        self.lay.setContentsMargins(10, 10, 10, 10)

        # space shortcut to close / toggle play
        self.spaceShortcut = QShortcut(QKeySequence(Qt.Key.Key_Space), self)
        self.spaceShortcut.activated.connect(self.onSpacePressed)

        # esc shortcut to close viewer (works regardless of IME)
        self.escShortcut = QShortcut(QKeySequence(Qt.Key.Key_Escape), self)
        self.escShortcut.activated.connect(self.close)

        self.ext = fileName.split('.')[-1].lower()
        if self.ext in ['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg']:
            self._showImg()
        elif self.ext in ['mp4', 'webm', 'mov', 'mkv']:
            self._showVid()
        elif self.ext in ['txt', 'md', 'csv', 'py', 'json', 'log']:
            self._showTxt()
        elif self.ext == 'pdf':
            self._showPdf()
        else:
            lbl = QLabel("Unsupported file type for internal viewer.")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.lay.addWidget(lbl)

    def _showImg(self):
        import requests
        self.lbl = ScaleLabel()
        self.lay.addWidget(self.lbl, 1)

        # zoom UI controls layout
        ctrlLay = QHBoxLayout()
        
        zoomOutBtn = QPushButton("Zoom -")
        zoomOutBtn.clicked.connect(self.lbl.zoomOut)
        
        zoomInBtn = QPushButton("Zoom +")
        zoomInBtn.clicked.connect(self.lbl.zoomIn)
        
        fitBtn = QPushButton("Fit Screen")
        fitBtn.clicked.connect(self.lbl.resetZoom)
        
        origBtn = QPushButton("100% (Original)")
        origBtn.clicked.connect(self.lbl.originalSize)
        
        self.zoomLbl = QLabel("Zoom: 100%")
        self.zoomLbl.setMinimumWidth(100)
        self.zoomLbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        ctrlLay.addWidget(zoomOutBtn)
        ctrlLay.addWidget(zoomInBtn)
        ctrlLay.addWidget(fitBtn)
        ctrlLay.addWidget(origBtn)
        ctrlLay.addWidget(self.zoomLbl)
        ctrlLay.addStretch()
        
        self.lay.addLayout(ctrlLay)
        
        # Connect signal to update zoom label
        self.lbl.zoomChanged.connect(self._updateZoomLbl)

        try:
            res = requests.get(self.fileUrl)
            self.lbl.setPixmap(QPixmap.fromImage(QImage.fromData(res.content)))
        except Exception as e:
            self.lay.addWidget(QLabel(f"Failed to load image: {e}"))

    def _updateZoomLbl(self, scale):
        self.zoomLbl.setText(f"Zoom: {int(scale * 100)}%")

    def _showTxt(self):
        import requests
        txt = QTextEdit()
        txt.setReadOnly(True)
        try:
            res = requests.get(self.fileUrl)
            txt.setText(res.content.decode('utf-8', errors='replace'))
        except Exception as e:
            txt.setText(f"Error: {e}")
        self.lay.addWidget(txt)

    def _showVid(self):
        try:
            from PyQt6.QtMultimedia import QMediaPlayer, QAudioOutput
            from PyQt6.QtMultimediaWidgets import QVideoWidget
        except ImportError:
            lbl = QLabel("QtMultimedia is not available.")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.lay.addWidget(lbl)
            return

        self.vidW = QVideoWidget()
        self.lay.addWidget(self.vidW)
        self.player = QMediaPlayer()
        self.audio = QAudioOutput()
        self.audio.setVolume(1.0)
        self.player.setAudioOutput(self.audio)
        self.player.setVideoOutput(self.vidW)
        self.player.setSource(QUrl(self.fileUrl))

        # seek bar
        seekLay = QHBoxLayout()
        self.timeLbl = QLabel("00:00 / 00:00")
        self.seekBar = ClickSldr(Qt.Orientation.Horizontal)
        self.seekBar.setRange(0, 0)
        self.seekBar.sliderMoved.connect(self.player.setPosition)
        self.player.positionChanged.connect(self._onPos)
        self.player.durationChanged.connect(lambda d: self.seekBar.setRange(0, d))
        seekLay.addWidget(self.timeLbl)
        seekLay.addWidget(self.seekBar)
        self.lay.addLayout(seekLay)

        # controls
        ctrlLay = QHBoxLayout()
        playBtn = QPushButton("Play / Pause")
        playBtn.clicked.connect(self._toggle)
        volLbl = QLabel("Volume:")
        self.volSldr = QSlider(Qt.Orientation.Horizontal)
        self.volSldr.setRange(0, 100)
        self.volSldr.setValue(100)
        self.volSldr.valueChanged.connect(lambda v: self.audio.setVolume(v / 100.0))
        ctrlLay.addWidget(playBtn)
        ctrlLay.addStretch()
        ctrlLay.addWidget(volLbl)
        ctrlLay.addWidget(self.volSldr)
        self.lay.addLayout(ctrlLay)
        self.player.play()

    def _onPos(self, pos):
        self.seekBar.setValue(pos)
        p, d = pos // 1000, self.player.duration() // 1000
        self.timeLbl.setText(f"{p//60:02d}:{p%60:02d} / {d//60:02d}:{d%60:02d}")

    def _toggle(self):
        if hasattr(self, 'player'):
            from PyQt6.QtMultimedia import QMediaPlayer
            if self.player.playbackState() == QMediaPlayer.PlaybackState.PlayingState:
                self.player.pause()
            else:
                self.player.play()

    def onSpacePressed(self):
        if hasattr(self, 'player') and self.player is not None:
            from PyQt6.QtMultimedia import QMediaPlayer
            if self.player.playbackState() == QMediaPlayer.PlaybackState.PlayingState:
                self.player.pause()
                self._overlay("⏸  Paused")
            else:
                self.player.play()
                self._overlay("▶  Playing")
        else:
            self.close()

    def keyPressEvent(self, ev):
        if hasattr(self, 'player') and self.player is not None:
            key = ev.key()
            if key in (Qt.Key.Key_Up, Qt.Key.Key_Down):
                v = self.volSldr.value() + (5 if key == Qt.Key.Key_Up else -5)
                v = max(0, min(100, v))
                self.volSldr.setValue(v)
                self._overlay(f"Volume: {v}%")
            elif key in (Qt.Key.Key_Left, Qt.Key.Key_Right):
                off = 10000 if key == Qt.Key.Key_Right else -10000
                self.player.setPosition(max(0, min(self.player.duration(), self.player.position() + off)))
                self._overlay(f"Seek: {'+10s' if off > 0 else '-10s'}")
            else:
                super().keyPressEvent(ev)
        else:
            if hasattr(self, 'ext') and self.ext not in ['mp4', 'webm', 'mov', 'mkv']:
                if self.ext == 'pdf' and ev.key() == Qt.Key.Key_Left:
                    self._prevPdfPage()
                    return
                if self.ext == 'pdf' and ev.key() == Qt.Key.Key_Right:
                    self._nextPdfPage()
                    return
                    
                if ev.key() in (Qt.Key.Key_Up, Qt.Key.Key_Down, Qt.Key.Key_Left, Qt.Key.Key_Right):
                    p = self.parent()
                    if p and hasattr(p, 'fileStack'):
                        new_row = None
                        if p.fileStack.currentIndex() == 0:
                            tbl = p.fileTbl
                            sel = tbl.selectionModel().selectedRows()
                            if sel and ev.key() in (Qt.Key.Key_Up, Qt.Key.Key_Down):
                                r = sel[0].row()
                                new_row = r - 1 if ev.key() == Qt.Key.Key_Up else r + 1
                                if 0 <= new_row < tbl.rowCount():
                                    tbl.selectRow(new_row)
                                    QTimer.singleShot(0, p.doView)
                        else:
                            lst = p.fileIconList
                            sel = lst.selectedItems()
                            if sel:
                                curr = sel[0]
                                r = lst.row(curr)
                                cols = max(1, lst.viewport().width() // lst.gridSize().width())
                                if ev.key() == Qt.Key.Key_Left:
                                    new_row = r - 1
                                elif ev.key() == Qt.Key.Key_Right:
                                    new_row = r + 1
                                elif ev.key() == Qt.Key.Key_Up:
                                    new_row = r - cols
                                elif ev.key() == Qt.Key.Key_Down:
                                    new_row = r + cols
                                
                                if new_row is not None and 0 <= new_row < lst.count():
                                    lst.setCurrentRow(new_row)
                                    QTimer.singleShot(0, p.doView)
                    return
            super().keyPressEvent(ev)

    def _overlay(self, text):
        if not hasattr(self, '_ovLbl'):
            self._ovLbl = QLabel()
            self._ovLbl.setWindowFlags(
                Qt.WindowType.FramelessWindowHint |
                Qt.WindowType.WindowStaysOnTopHint |
                Qt.WindowType.Tool |
                Qt.WindowType.WindowTransparentForInput)
            self._ovLbl.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
            self._ovLbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            self._ovLbl.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
            self._ovLbl.setStyleSheet("""
                QLabel { color: white; background-color: rgba(0,0,0,180);
                         padding: 12px 18px; border-radius: 8px;
                         font-size: 22px; font-weight: bold; }
            """)
            from PyQt6.QtCore import QTimer
            self._ovTimer = QTimer(self)
            self._ovTimer.setSingleShot(True)
            self._ovTimer.timeout.connect(self._ovLbl.hide)

        self._ovLbl.setText(text)
        self._ovLbl.adjustSize()
        gp = self.vidW.mapToGlobal(self.vidW.rect().topLeft())
        self._ovLbl.move(gp.x() + 20, gp.y() + 20)
        self._ovLbl.show()
        self._ovLbl.raise_()
        self._ovTimer.start(1500)

    def _showPdf(self):
        import requests
        try:
            import fitz
        except ImportError:
            lbl = QLabel("PyMuPDF (fitz) is not installed.\nRun: pip install PyMuPDF")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.lay.addWidget(lbl)
            return

        self.pdfDoc = None
        self.pdfPage = 0
        
        try:
            res = requests.get(self.fileUrl)
            self.pdfDoc = fitz.open(stream=res.content, filetype="pdf")
        except Exception as e:
            lbl = QLabel(f"Failed to load PDF: {e}")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.lay.addWidget(lbl)
            return

        if not self.pdfDoc or self.pdfDoc.page_count == 0:
            lbl = QLabel("PDF is empty or invalid.")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.lay.addWidget(lbl)
            return

        self.lbl = ScaleLabel()
        self.lay.addWidget(self.lbl, 1)

        ctrlLay = QHBoxLayout()
        zoomOutBtn = QPushButton("Zoom -")
        zoomOutBtn.clicked.connect(self.lbl.zoomOut)
        zoomInBtn = QPushButton("Zoom +")
        zoomInBtn.clicked.connect(self.lbl.zoomIn)
        fitBtn = QPushButton("Fit Screen")
        fitBtn.clicked.connect(self.lbl.resetZoom)
        
        self.zoomLbl = QLabel("Zoom: 100%")
        self.zoomLbl.setMinimumWidth(80)
        self.zoomLbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        prevBtn = QPushButton("Prev Page")
        prevBtn.clicked.connect(self._prevPdfPage)
        
        nextBtn = QPushButton("Next Page")
        nextBtn.clicked.connect(self._nextPdfPage)
        
        self.pageLbl = QLabel(f"Page: 1 / {self.pdfDoc.page_count}")
        self.pageLbl.setMinimumWidth(100)
        self.pageLbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        ctrlLay.addWidget(zoomOutBtn)
        ctrlLay.addWidget(zoomInBtn)
        ctrlLay.addWidget(fitBtn)
        ctrlLay.addWidget(self.zoomLbl)
        ctrlLay.addStretch()
        ctrlLay.addWidget(prevBtn)
        ctrlLay.addWidget(self.pageLbl)
        ctrlLay.addWidget(nextBtn)
        
        self.lay.addLayout(ctrlLay)
        self.lbl.zoomChanged.connect(self._updateZoomLbl)
        self._renderPdfPage()

    def _renderPdfPage(self):
        import fitz
        if not hasattr(self, 'pdfDoc') or not self.pdfDoc: return
        page = self.pdfDoc.load_page(self.pdfPage)
        mat = fitz.Matrix(2.0, 2.0)
        pix = page.get_pixmap(matrix=mat)
        
        from PyQt6.QtGui import QImage, QPixmap
        fmt = QImage.Format.Format_RGBA8888 if pix.alpha else QImage.Format.Format_RGB888
        img = QImage(pix.samples, pix.width, pix.height, pix.stride, fmt)
        self.lbl.setPixmap(QPixmap.fromImage(img))
        self.pageLbl.setText(f"Page: {self.pdfPage + 1} / {self.pdfDoc.page_count}")
        
    def _prevPdfPage(self):
        if hasattr(self, 'pdfDoc') and self.pdfDoc and self.pdfPage > 0:
            self.pdfPage -= 1
            self._renderPdfPage()
            
    def _nextPdfPage(self):
        if hasattr(self, 'pdfDoc') and self.pdfDoc and self.pdfPage < self.pdfDoc.page_count - 1:
            self.pdfPage += 1
            self._renderPdfPage()

    def closeEvent(self, ev):
        if hasattr(self, '_ovLbl') and self._ovLbl is not None:
            self._ovLbl.hide()
            self._ovLbl.deleteLater()
            self._ovLbl = None
        if hasattr(self, 'player'):
            self.player.stop()
            self.player.setSource(QUrl(""))
        if hasattr(self, 'web') and self.web is not None:
            self.web.load(QUrl(""))
        if hasattr(self, 'pdfDoc') and self.pdfDoc is not None:
            self.pdfDoc.close()
            self.pdfDoc = None
        super().closeEvent(ev)


# --- Main Application ---

def _emojiIcon(text):
    pm = QPixmap(64, 64)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    font = p.font()
    font.setPointSize(36)
    p.setFont(font)
    p.drawText(pm.rect(), Qt.AlignmentFlag.AlignCenter, text)
    p.end()
    return QIcon(pm)

class MHApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.proxy = MHProxy(port=18080)
        self.proxy.start()
        self.cli = None
        self.curFld = None
        self.curPid = None
        self.curKey = None
        self.curFiles = {}

        self.setWindowTitle("MediaHub Desktop")
        self.resize(1000, 700)
        self.setStyleSheet("""
            QMainWindow { 
                background-color: #2C2C2E; 
                color: #FFFFFF; 
            }
            QWidget { font-family: 'Pretendard Variable', -apple-system, BlinkMacSystemFont, 'SF Pro Text', 'Segoe UI', sans-serif; font-size: 13px; }
            QLabel { color: #FFFFFF; }
            QLineEdit { background-color: rgba(0, 0, 0, 0.4); color: #FFFFFF; border: 1px solid #3A3A3C; border-radius: 8px; padding: 7px 10px; selection-background-color: rgba(255, 255, 255, 0.3); }
            QLineEdit:focus { border: 1px solid #0A84FF; background-color: rgba(0, 0, 0, 0.6); }
            QPushButton { background-color: rgba(255, 255, 255, 0.1); color: #FFFFFF; border: 1px solid #48484A; border-radius: 8px; padding: 8px 16px; font-weight: 500; }
            QPushButton:hover { background-color: rgba(255, 255, 255, 0.2); border-color: #5C5C5E; }
            QPushButton:pressed { background-color: rgba(255, 255, 255, 0.05); }
            QPushButton:disabled { background-color: rgba(0, 0, 0, 0.2); color: rgba(255, 255, 255, 0.3); border-color: transparent; }
            QListWidget, QTableWidget { background-color: rgba(0, 0, 0, 0.2); color: #FFFFFF; border: none; outline: 0; selection-background-color: transparent; }
            QListWidget::item { padding: 6px 10px; border-radius: 4px; margin: 2px 4px; }
            QListWidget::item:selected { background-color: rgba(255, 255, 255, 0.15); color: #FFFFFF; border-radius: 4px; }
            QTableWidget::item:selected { background-color: transparent; color: #FFFFFF; }
            QHeaderView::section { background-color: transparent; color: rgba(255, 255, 255, 0.7); padding: 4px 8px; border: none; border-bottom: 1px solid rgba(255, 255, 255, 0.1); font-weight: 500; }
            QTableWidget QTableCornerButton::section { background-color: transparent; }
            QCheckBox { color: #FFFFFF; spacing: 6px; }
            QCheckBox::indicator { width: 16px; height: 16px; border-radius: 4px; border: 1px solid rgba(255, 255, 255, 0.2); background-color: rgba(0, 0, 0, 0.3); }
            QCheckBox::indicator:checked { background-color: rgba(255, 255, 255, 0.3); border-color: rgba(255, 255, 255, 0.5); }
            QScrollBar:vertical { border: none; background: transparent; width: 8px; margin: 0px 0px 0px 0px; }
            QScrollBar::handle:vertical { background: rgba(255, 255, 255, 0.2); min-height: 20px; border-radius: 4px; }
            QScrollBar::handle:vertical:hover { background: rgba(255, 255, 255, 0.4); }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { border: none; background: none; height: 0px; }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: none; border: none; }
            QScrollBar:horizontal { border: none; background: transparent; height: 8px; margin: 0px 0px 0px 0px; }
            QScrollBar::handle:horizontal { background: rgba(255, 255, 255, 0.2); min-width: 20px; border-radius: 4px; }
            QScrollBar::handle:horizontal:hover { background: rgba(255, 255, 255, 0.4); }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { border: none; background: none; width: 0px; }
            QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal { background: none; border: none; }
        """)

        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)
        self._initLog()
        self._initMain()

        # auto-login from keyring
        cred = self._loadCred()
        if cred:
            self.urlIn.setText(cred['url'])
            self.userIn.setText(cred['user'])
            self.autoChk.setChecked(True)
            self.ignTlsChk.setChecked(cred.get('ignTls', False))
            self.cli = MHClient(cred['url'], cred['user'], "", verify_ssl=not cred.get('ignTls', False))
            self.cli.setAuth(cred['uHash'], cred['uKey'])
            self.stack.setCurrentIndex(1)
            self.doFlds()
        else:
            self.stack.setCurrentIndex(0)

    # --- Keyring ---

    def _loadCred(self):
        if not HAS_KEYRING:
            return None
        try:
            raw = keyring.get_password(KR_SVC, KR_ACC)
            if not raw:
                return None
            d = json.loads(raw)
            return {'url': d['url'], 'user': d['user'],
                    'uHash': d['uHash'], 'uKey': bytes.fromhex(d['uKey']),
                    'ignTls': d.get('ignTls', False)}
        except Exception:
            return None

    def _saveCred(self, url, user, uHash, uKey, ignTls):
        if not HAS_KEYRING:
            return
        try:
            keyring.set_password(KR_SVC, KR_ACC, json.dumps({
                'url': url, 'user': user,
                'uHash': uHash, 'uKey': uKey.hex(), 'ignTls': ignTls}))
        except Exception:
            pass

    def _clrCred(self):
        if HAS_KEYRING:
            try:
                keyring.delete_password(KR_SVC, KR_ACC)
            except Exception:
                pass

    # --- Login UI ---

    def _initLog(self):
        w = QWidget()
        lay = QVBoxLayout()
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title = QLabel("MediaHub")
        title.setStyleSheet("font-size: 32px; font-weight: bold; color: #FFFFFF; margin-bottom: 20px;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.urlIn = QLineEdit()
        self.urlIn.setPlaceholderText("Server Address (e.g., https://localhost:443)")
        self.urlIn.setFixedWidth(300)

        self.userIn = QLineEdit()
        self.userIn.setPlaceholderText("Username")
        self.userIn.setFixedWidth(300)

        self.passIn = QLineEdit()
        self.passIn.setPlaceholderText("Password")
        self.passIn.setEchoMode(QLineEdit.EchoMode.Password)
        self.passIn.setFixedWidth(300)

        self.ignTlsChk = QCheckBox("Ignore TLS Warnings")
        self.ignTlsChk.setFixedWidth(300)

        self.autoChk = QCheckBox("Auto Login")
        self.autoChk.setFixedWidth(300)

        self.logBtn = QPushButton("Login")
        self.logBtn.setFixedWidth(300)
        self.logBtn.clicked.connect(self.doLogin)

        self.statLbl = QLabel("")
        self.statLbl.setStyleSheet("color: #FF453A;")
        self.statLbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        lay.addWidget(title)
        lay.addWidget(self.urlIn)
        lay.addWidget(self.userIn)
        lay.addWidget(self.passIn)
        lay.addWidget(self.ignTlsChk)
        lay.addWidget(self.autoChk)
        lay.addWidget(self.logBtn)
        lay.addWidget(self.statLbl)
        w.setLayout(lay)
        self.stack.addWidget(w)

    # --- Main UI ---

    def _initMain(self):
        w = QWidget()
        # Main layout is vertical (Top Bar + Split Content)
        mainLay = QVBoxLayout()
        mainLay.setContentsMargins(0, 0, 0, 0)
        mainLay.setSpacing(0)

        # --- Top Toolbar ---
        topBar = QWidget()
        topBar.setObjectName("topBar")
        topBar.setStyleSheet("#topBar { background-color: rgba(255, 255, 255, 0.05); border-bottom: 1px solid rgba(255, 255, 255, 0.1); }")
        topLay = QHBoxLayout()
        topLay.setContentsMargins(15, 10, 15, 10)

        def _icon(name):
            return QIcon(os.path.join(os.path.dirname(__file__), "icons", f"{name}.svg"))

        # Action Buttons
        self.refBtn = QPushButton("Refresh")
        self.refBtn.setIcon(_icon("refresh"))
        self.refBtn.clicked.connect(self.doFlds)
        
        self.newBtn = QPushButton("New Folder")
        self.newBtn.setIcon(_icon("new-folder"))
        self.newBtn.clicked.connect(self.doMkFld)
        
        self.upBtn = QPushButton("Upload")
        self.upBtn.setIcon(_icon("upload"))
        self.upBtn.clicked.connect(self.doUpload)
        
        self.upDirBtn = QPushButton("Upload Dir")
        self.upDirBtn.setIcon(_icon("folder-upload"))
        self.upDirBtn.clicked.connect(self.doUpDir)
        
        self.dnBtn = QPushButton("Download")
        self.dnBtn.setIcon(_icon("download"))
        self.dnBtn.clicked.connect(self.doDown)
        
        self.viewModeBtn = QPushButton("View")
        self.viewModeBtn.setIcon(_icon("view"))
        self.viewModeBtn.clicked.connect(self.doToggleViewMode)
        self.isIconView = False

        # Search Bar
        self.srchIn = QLineEdit()
        self.srchIn.setPlaceholderText("Search...")
        self.srchIn.addAction(_icon("search"), QLineEdit.ActionPosition.LeadingPosition)
        self.srchIn.setFixedWidth(200)
        self.srchIn.textChanged.connect(self.doFilter)

        self.logoutBtn = QPushButton("Logout")
        self.logoutBtn.setIcon(_icon("logout"))
        self.logoutBtn.setStyleSheet("background-color: transparent; color: #FF453A; font-size: 13px; font-weight: 500; border: 1px solid rgba(255, 69, 58, 0.5);")
        self.logoutBtn.clicked.connect(self.doLogout)

        topLay.addWidget(self.newBtn)
        topLay.addWidget(self.refBtn)
        topLay.addWidget(self.upBtn)
        topLay.addWidget(self.upDirBtn)
        topLay.addWidget(self.dnBtn)
        topLay.addWidget(self.viewModeBtn)
        topLay.addStretch()
        topLay.addWidget(self.srchIn)
        topLay.addWidget(self.logoutBtn)
        topBar.setLayout(topLay)

        # --- Split Area ---
        splitWidget = QWidget()
        splitLay = QHBoxLayout()
        splitLay.setContentsMargins(0, 0, 0, 0)
        splitLay.setSpacing(0)

        # Sidebar
        sb = QWidget()
        sb.setObjectName("sideBar")
        sb.setFixedWidth(250)
        sb.setStyleSheet("#sideBar { background-color: rgba(0, 0, 0, 0.2); border-right: 1px solid rgba(255, 255, 255, 0.1); }")
        sbLay = QVBoxLayout()
        sbLay.setContentsMargins(10, 15, 10, 15)

        fldLbl = QLabel("Folders")
        fldLbl.setStyleSheet("font-size: 13px; font-weight: 600; margin-bottom: 5px; margin-left: 5px; color: rgba(255, 255, 255, 0.6);")

        self.fldList = QListWidget()
        self.fldList.itemClicked.connect(self.onFldSel)
        self.fldList.setStyleSheet("background: transparent; border: none;")

        sbLay.addWidget(fldLbl)
        sbLay.addWidget(self.fldList)
        sb.setLayout(sbLay)

        # Content Area
        ct = QWidget()
        ct.setStyleSheet("background-color: transparent;")
        ctLay = QVBoxLayout()
        ctLay.setContentsMargins(20, 15, 20, 20)

        self.curLbl = QLabel("Select a folder")
        self.curLbl.setStyleSheet("font-size: 20px; font-weight: 700; color: #FFFFFF; margin-bottom: 10px; background: transparent; border: none;")

        self.fileStack = QStackedWidget()

        self.fileTbl = QTableWidget(0, 3)
        self.fileTbl.setHorizontalHeaderLabels(["", "Filename", "Size"])
        self.fileTbl.setStyleSheet("background-color: transparent; border: none;")
        self.fileTbl.setShowGrid(False)
        self.fileTbl.setItemDelegate(RowSelectionDelegate(self.fileTbl))
        
        self.fileTbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.fileTbl.setColumnWidth(0, 40)
        self.fileTbl.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.fileTbl.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.fileTbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.fileTbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.fileTbl.itemDoubleClicked.connect(self.doView)
        self.fileTbl.setSortingEnabled(True)
        self.fileTbl.horizontalHeader().setSortIndicator(-1, Qt.SortOrder.AscendingOrder)
        self.fileTbl.verticalHeader().setDefaultSectionSize(26)
        self.fileTbl.verticalHeader().hide()
        
        self.fileIconList = QListWidget()
        self.fileIconList.setViewMode(QListWidget.ViewMode.IconMode)
        self.fileIconList.setResizeMode(QListWidget.ResizeMode.Adjust)
        self.fileIconList.setMovement(QListWidget.Movement.Static)
        self.fileIconList.setGridSize(QSize(120, 100))
        self.fileIconList.setIconSize(QSize(64, 64))
        self.fileIconList.setSpacing(10)
        self.fileIconList.setStyleSheet("background-color: transparent; border: none; outline: 0;")
        self.fileIconList.itemDoubleClicked.connect(self.doView)
        
        self.fileStack.addWidget(self.fileTbl)
        self.fileStack.addWidget(self.fileIconList)

        self.tableSpaceShortcut = QShortcut(QKeySequence(Qt.Key.Key_Space), self.fileStack)
        self.tableSpaceShortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self.tableSpaceShortcut.activated.connect(self.doView)

        self.progBar = QProgressBar()
        self.progBar.setVisible(False)
        self.progBar.setRange(0, 100)
        self.progBar.setTextVisible(False)
        self.progBar.setStyleSheet("""
            QProgressBar { border: none; border-radius: 4px; background-color: rgba(0, 0, 0, 0.3); height: 8px; }
            QProgressBar::chunk { background-color: #0A84FF; border-radius: 4px; }
        """)
        self.upStatLbl = QLabel("")
        self.upStatLbl.setVisible(False)
        self.upStatLbl.setStyleSheet("color: #FFFFFF; font-size: 12px; font-weight: 500; background: transparent; border: none;")

        ctLay.addWidget(self.curLbl)
        ctLay.addWidget(self.fileStack)
        ctLay.addWidget(self.upStatLbl)
        ctLay.addWidget(self.progBar)
        ct.setLayout(ctLay)

        splitLay.addWidget(sb)
        splitLay.addWidget(ct)
        splitWidget.setLayout(splitLay)

        mainLay.addWidget(topBar)
        mainLay.addWidget(splitWidget)
        w.setLayout(mainLay)
        self.stack.addWidget(w)

    # --- Actions ---

    def doToggleViewMode(self):
        self.isIconView = not self.isIconView
        self.fileStack.setCurrentIndex(1 if self.isIconView else 0)

    def doFilter(self, text):
        s = unicodedata.normalize('NFC', text).lower()
        for r in range(self.fileTbl.rowCount()):
            it = self.fileTbl.item(r, 1)
            if it:
                self.fileTbl.setRowHidden(r, s not in unicodedata.normalize('NFC', it.text()).lower())
        for i in range(self.fileIconList.count()):
            it = self.fileIconList.item(i)
            it.setHidden(s not in unicodedata.normalize('NFC', it.text()).lower())

    def doLogin(self):
        url = self.urlIn.text().strip()
        user = self.userIn.text().strip()
        pw = self.passIn.text()
        if not url or not user or not pw:
            self.statLbl.setText("Please fill all fields")
            return
        self.logBtn.setEnabled(False)
        self.statLbl.setText("Authenticating...")
        ign_tls = self.ignTlsChk.isChecked()
        self.cli = MHClient(url, user, pw, verify_ssl=not ign_tls)
        self._wk = WkLogin(self.cli)
        self._wk.success.connect(self._onLogOk)
        self._wk.error.connect(self._onLogErr)
        self._wk.start()

    def _onLogOk(self):
        if self.autoChk.isChecked():
            self._saveCred(self.urlIn.text().strip(), self.userIn.text().strip(),
                           self.cli.uHash, self.cli.uKey, self.ignTlsChk.isChecked())
        self.passIn.clear()
        self.stack.setCurrentIndex(1)
        self.doFlds()

    def _onLogErr(self, err):
        self.logBtn.setEnabled(True)
        self.statLbl.setText(f"Error: {err}")

    def doLogout(self):
        self._clrCred()
        self.cli = None
        self.fldList.clear()
        self.fileTbl.setRowCount(0)
        self.fileIconList.clear()
        self.passIn.clear()
        self.ignTlsChk.setChecked(False)
        self.autoChk.setChecked(False)
        self.stack.setCurrentIndex(0)
        self.logBtn.setEnabled(True)
        self.statLbl.setText("")

    def doFlds(self):
        self.fldList.clear()
        self._wk = WkFlds(self.cli)
        self._wk.success.connect(self._onFlds)
        self._wk.error.connect(lambda e: QMessageBox.critical(self, "Error", f"Failed to fetch folders: {e}"))
        self._wk.start()

    def _onFlds(self, flds):
        self.fldList.clear()
        for f in flds.keys():
            self.fldList.addItem(f)

    def doMkFld(self):
        name, ok = QInputDialog.getText(self, "New Folder", "Folder Name:")
        if ok and name:
            try:
                self.cli.mkFld(name)
                self.doFlds()
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def onFldSel(self, item):
        self.curFld = item.text()
        self.curLbl.setText(self.curFld)
        self.fileTbl.setRowCount(0)
        self.fileIconList.clear()
        self._wk = WkFiles(self.cli, self.curFld)
        self._wk.success.connect(self._onFiles)
        self._wk.error.connect(lambda e: QMessageBox.critical(self, "Error", f"Failed to fetch files: {e}"))
        self._wk.start()

    def _fmtSize(self, sz):
        for u in ['B', 'KB', 'MB', 'GB', 'TB']:
            if sz < 1024.0:
                return f"{sz:.1f} {u}" if u != 'B' else f"{sz} {u}"
            sz /= 1024.0
        return f"{sz:.1f} PB"

    def _onFiles(self, pid, key, files):
        self.curPid = pid
        self.curKey = key
        self.curFiles = files
        self.proxy.updCtx(self.cli, files)
        self._thumbWk = []

        IMG = {'jpg', 'jpeg', 'png', 'gif', 'webp', 'svg'}
        VID = {'mp4', 'webm', 'mov', 'mkv'}
        TXT = {'txt', 'md', 'csv', 'py', 'json', 'log'}

        self.fileTbl.setSortingEnabled(False)
        self.fileTbl.setRowCount(0)
        self.fileIconList.clear()

        for name, info in files.items():
            sz = Opsec.DecodeInt(info[44:52], False)
            row = self.fileTbl.rowCount()
            self.fileTbl.insertRow(row)
            self.fileTbl.setRowHeight(row, 26)

            thLbl = QLabel()
            thLbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            ext = name.rsplit('.', 1)[-1].lower() if '.' in name else ''
            
            iconItem = QListWidgetItem(name)
            iconItem.setData(Qt.ItemDataRole.UserRole, name.lower())
            iconItem.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            if ext == 'svg':
                thLbl.setText("🎨"); thLbl.setStyleSheet("font-size:18px;")
                iconItem.setIcon(_emojiIcon("🎨"))
            elif ext in IMG | VID:
                thLbl.setText("⏳")
                thLbl.setStyleSheet("color:#888; font-size:16px;")
                fk = info[:44]
                fpid = self.cli.objPid(fk)
                thLbl.setProperty("fpid", fpid)
                iconItem.setData(Qt.ItemDataRole.UserRole + 1, fpid)
                w = WkThumb(self.cli, pid, fpid, fk)
                w.success.connect(self._onThumb)
                w.start()
                self._thumbWk.append(w)
            elif ext == 'pdf':
                thLbl.setText("📄"); thLbl.setStyleSheet("font-size:18px;")
                iconItem.setIcon(_emojiIcon("📄"))
            elif ext in TXT:
                thLbl.setText("📝"); thLbl.setStyleSheet("font-size:18px;")
                iconItem.setIcon(_emojiIcon("📝"))
            else:
                thLbl.setText("📁"); thLbl.setStyleSheet("font-size:18px;")
                iconItem.setIcon(_emojiIcon("📁"))

            self.fileTbl.setCellWidget(row, 0, thLbl)
            self.fileTbl.setItem(row, 0, SortItem(""))

            nItem = SortItem(name)
            nItem.setData(Qt.ItemDataRole.UserRole, name.lower())
            sItem = SortItem(self._fmtSize(sz))
            sItem.setData(Qt.ItemDataRole.UserRole, sz)

            self.fileTbl.setItem(row, 1, nItem)
            self.fileTbl.setItem(row, 2, sItem)
            self.fileIconList.addItem(iconItem)

        self.fileTbl.setSortingEnabled(True)
        self.fileIconList.sortItems()
        self.doFilter(self.srchIn.text())

    def _onThumb(self, fpid, raw):
        # QPixmap must be created on GUI thread
        pm = QPixmap.fromImage(QImage.fromData(raw))
        if pm.isNull():
            return
        scaled = pm.scaled(18, 18, Qt.AspectRatioMode.KeepAspectRatio,
                           Qt.TransformationMode.SmoothTransformation)
        for r in range(self.fileTbl.rowCount()):
            lbl = self.fileTbl.cellWidget(r, 0)
            if lbl and lbl.property("fpid") == fpid:
                lbl.setPixmap(scaled)
                break
                
        scaled_large = pm.scaled(64, 64, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
        for i in range(self.fileIconList.count()):
            it = self.fileIconList.item(i)
            if it.data(Qt.ItemDataRole.UserRole + 1) == fpid:
                it.setIcon(QIcon(scaled_large))
                break

    def _setLoad(self, on=True):
        self.upBtn.setEnabled(not on)
        self.upDirBtn.setEnabled(not on)
        self.dnBtn.setEnabled(not on)
        self.viewModeBtn.setEnabled(not on)
        self.progBar.setVisible(on)
        self.upStatLbl.setVisible(on)
        if on:
            self.progBar.setRange(0, 100)
            self.progBar.setValue(0)
            self.upStatLbl.setText("Preparing...")

    def _onUpProg(self, sent, total, speed):
        if total > 0:
            pct = int(sent * 100 / total)
            self.progBar.setValue(pct)
            if speed > 0:
                self.upStatLbl.setText(f"Uploading... {pct}%  |  {speed / (1024*1024):.1f} MB/s")
            else:
                self.upStatLbl.setText(f"Uploading... {pct}%")

    def doUpload(self):
        if not self.curFld:
            QMessageBox.warning(self, "Warning", "Select a folder first")
            return
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files to Upload")
        if files:
            self._setLoad(True)
            self._wk = WkUpload(self.cli, self.curPid, self.curKey, self.curFiles, files)
            self._wk.success.connect(self._onUpDone)
            self._wk.error.connect(self._onOpErr)
            self._wk.progress.connect(self._onUpProg)
            self._wk.start()

    def doUpDir(self):
        if not self.curFld:
            QMessageBox.warning(self, "Warning", "Select a folder first")
            return
        dp = QFileDialog.getExistingDirectory(self, "Select Directory to Upload")
        if dp:
            files = [os.path.join(dp, f) for f in os.listdir(dp) if os.path.isfile(os.path.join(dp, f))]
            if files:
                self._setLoad(True)
                self._wk = WkUpload(self.cli, self.curPid, self.curKey, self.curFiles, files)
                self._wk.success.connect(self._onUpDone)
                self._wk.error.connect(self._onOpErr)
                self._wk.progress.connect(self._onUpProg)
                self._wk.start()

    def _onUpDone(self):
        self._setLoad(False)
        self.upStatLbl.setVisible(False)
        QMessageBox.information(self, "Success", "Upload complete!")
        self.onFldSel(self.fldList.currentItem())

    def doDown(self):
        if not self.curFld:
            QMessageBox.warning(self, "Warning", "Select a folder first")
            return
        sel = self.fileTbl.selectionModel().selectedRows()
        if not sel:
            QMessageBox.warning(self, "Warning", "Select files to download")
            return
        outDir = QFileDialog.getExistingDirectory(self, "Select Download Directory")
        if outDir:
            self._setLoad(True)
            row = sel[0].row()
            name = self.fileTbl.item(row, 1).text()
            flInfo = self.curFiles[name]
            self._wk = WkDown(self.cli, self.curPid, flInfo, name, outDir)
            self._wk.success.connect(self._onDnDone)
            self._wk.error.connect(self._onOpErr)
            self._wk.start()

    def _onDnDone(self, path):
        self._setLoad(False)
        QMessageBox.information(self, "Success", f"Downloaded to:\n{path}")

    def doView(self):
        if not self.curFld:
            QMessageBox.warning(self, "Warning", "Select a folder first")
            return
        if self.fileStack.currentIndex() == 0:
            sel = self.fileTbl.selectionModel().selectedRows()
            if not sel:
                QMessageBox.warning(self, "Warning", "Select a file to view")
                return
            row = sel[0].row()
            name = self.fileTbl.item(row, 1).text()
        else:
            sel = self.fileIconList.selectedItems()
            if not sel:
                QMessageBox.warning(self, "Warning", "Select a file to view")
                return
            name = sel[0].text()
        url = f"http://127.0.0.1:18080/stream/{self.curPid}/{urllib.parse.quote(name)}"
        
        if hasattr(self, 'viewer') and self.viewer:
            self.viewer.close()
            self.viewer.deleteLater()
            
        self.viewer = Viewer(url, name, parent=self)
        self.viewer.show()

    def _onOpErr(self, err):
        self._setLoad(False)
        QMessageBox.critical(self, "Error", str(err))

    def closeEvent(self, ev):
        self.proxy.stop()
        super().closeEvent(ev)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    font_path = os.path.join(os.path.dirname(__file__), "fonts", "PretendardVariable.ttf")
    font_id = QFontDatabase.addApplicationFont(font_path)
    if font_id != -1:
        font_family = QFontDatabase.applicationFontFamilies(font_id)[0]
        app.setFont(QFont(font_family, 13))
        
    win = MHApp()
    win.show()
    sys.exit(app.exec())
