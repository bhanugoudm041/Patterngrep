from burp import IBurpExtender, ITab, IHttpListener
from javax.swing import JPanel, JTable, JScrollPane, JTextField, JToggleButton, JLabel, JSplitPane, JTextArea, BoxLayout
from javax.swing.table import AbstractTableModel
from java.awt import BorderLayout
from java.awt.event import MouseAdapter, MouseEvent
import re

class BurpExtender(IBurpExtender, ITab, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Patterngrep")

        self._requests = []
        self._pattern = ""
        self._monitoring = False

        # Main panel setup
        self._main_panel = JPanel(BorderLayout())
        self._table_model = RequestTableModel(self)
        self._table = JTable(self._table_model)
        self._scroll_pane = JScrollPane(self._table)

        # Filter panel setup (using JToggleButton for monitor switch)
        self._filter_panel = JPanel()
        self._filter_panel.setLayout(BoxLayout(self._filter_panel, BoxLayout.X_AXIS))
        self._pattern_label = JLabel("Pattern: ")
        self._pattern_field = JTextField("", 20)
        self._monitor_toggle = JToggleButton("Monitor", actionPerformed=self.toggle_monitoring)
        self._filter_panel.add(self._pattern_label)
        self._filter_panel.add(self._pattern_field)
        self._filter_panel.add(self._monitor_toggle)

        # Request and Response content setup
        self._request_area = JTextArea()
        self._response_area = JTextArea()

        # Labels for headers
        self._request_header_label = JLabel("Request Headers and Body", JLabel.CENTER)
        self._response_header_label = JLabel("Response Headers and Body", JLabel.CENTER)

        # Setup panels for request and response content
        self._request_panel = JPanel(BorderLayout())
        self._request_panel.add(self._request_header_label, BorderLayout.NORTH)
        self._request_panel.add(JScrollPane(self._request_area), BorderLayout.CENTER)

        self._response_panel = JPanel(BorderLayout())
        self._response_panel.add(self._response_header_label, BorderLayout.NORTH)
        self._response_panel.add(JScrollPane(self._response_area), BorderLayout.CENTER)

        # Search functionality for request and response
        self._request_search_field = JTextField("", 20)
        self._request_search_button = JToggleButton("Search", actionPerformed=self.search_request)
        self._response_search_field = JTextField("", 20)
        self._response_search_button = JToggleButton("Search", actionPerformed=self.search_response)

        self._request_search_panel = JPanel()
        self._request_search_panel.setLayout(BoxLayout(self._request_search_panel, BoxLayout.X_AXIS))
        self._request_search_panel.add(JLabel("Search Request: "))
        self._request_search_panel.add(self._request_search_field)
        self._request_search_panel.add(self._request_search_button)

        self._response_search_panel = JPanel()
        self._response_search_panel.setLayout(BoxLayout(self._response_search_panel, BoxLayout.X_AXIS))
        self._response_search_panel.add(JLabel("Search Response: "))
        self._response_search_panel.add(self._response_search_field)
        self._response_search_panel.add(self._response_search_button)

        # Add search panels to request and response panels
        self._request_panel.add(self._request_search_panel, BorderLayout.SOUTH)
        self._response_panel.add(self._response_search_panel, BorderLayout.SOUTH)

        # Split pane for request and response
        self._request_response_split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, self._request_panel, self._response_panel)
        self._request_response_split_pane.setDividerLocation(500)  # Adjust this value to fit your needs

        # Main split pane setup
        self._main_split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, self._scroll_pane, self._request_response_split_pane)
        self._main_split_pane.setDividerLocation(300)

        # Add components to the main panel
        self._main_panel.add(self._filter_panel, BorderLayout.NORTH)
        self._main_panel.add(self._main_split_pane, BorderLayout.CENTER)

        self._table.addMouseListener(TableMouseListener(self))

        self._callbacks.addSuiteTab(self)
        self._callbacks.registerHttpListener(self)

    def getTabCaption(self):
        return "Patterngrep"

    def getUiComponent(self):
        return self._main_panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest and self._monitoring:
            request_info = self._helpers.analyzeRequest(messageInfo)
            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            response_body = messageInfo.getResponse()[response_info.getBodyOffset():].tostring()
            if re.search(self._pattern, response_body):
                self._requests.append(messageInfo)
                self._table_model.fireTableDataChanged()

    def toggle_monitoring(self, event):
        if self._monitoring:
            # Stop monitoring
            self._monitoring = False
            self._monitor_toggle.setText("Monitor")
            self._requests = []  # Clear current requests if needed
            self._table_model.fireTableDataChanged()
        else:
            # Start monitoring
            self._pattern = self._pattern_field.getText()
            if self._pattern:
                self._monitoring = True
                self._monitor_toggle.setText("Monitoring")
                self._requests = []  # Clear previous requests
                self._table_model.fireTableDataChanged()
            else:
                # Pattern is empty, just reset button
                self._monitoring = False
                self._monitor_toggle.setText("Monitor")

    def display_request_response(self, rowIndex):
        messageInfo = self._requests[rowIndex]
        request_info = self._helpers.analyzeRequest(messageInfo)
        response_info = self._helpers.analyzeResponse(messageInfo.getResponse())

        request_headers = "\n".join(request_info.getHeaders())
        request_body = self._helpers.bytesToString(messageInfo.getRequest()[request_info.getBodyOffset():])
        response_headers = "\n".join(response_info.getHeaders())
        response_body = self._helpers.bytesToString(messageInfo.getResponse()[response_info.getBodyOffset():])

        request_text = "{}\n\n{}".format(request_headers, request_body)
        response_text = "{}\n\n{}".format(response_headers, response_body)

        self._request_area.setText(request_text)
        self._response_area.setText(response_text)

        self._request_area.setCaretPosition(0)
        self._response_area.setCaretPosition(0)

    def search_request(self, event):
        search_text = self._request_search_field.getText()
        self._highlight_text(self._request_area, search_text)

    def search_response(self, event):
        search_text = self._response_search_field.getText()
        self._highlight_text(self._response_area, search_text)

    def _highlight_text(self, text_area, search_text):
        content = text_area.getText()
        start = content.lower().find(search_text.lower())
        if start != -1:
            end = start + len(search_text)
            text_area.select(start, end)
            text_area.requestFocus()

class RequestTableModel(AbstractTableModel):
    def __init__(self, extender):
        self._extender = extender
        self._column_names = ["Method", "URL", "Status", "Length"]

    def getColumnCount(self):
        return len(self._column_names)

    def getRowCount(self):
        return len(self._extender._requests)

    def getColumnName(self, columnIndex):
        return self._column_names[columnIndex]

    def getValueAt(self, rowIndex, columnIndex):
        messageInfo = self._extender._requests[rowIndex]
        request_info = self._extender._helpers.analyzeRequest(messageInfo)
        response_info = self._extender._helpers.analyzeResponse(messageInfo.getResponse())
        if columnIndex == 0:
            return request_info.getMethod()
        elif columnIndex == 1:
            return request_info.getUrl().toString()
        elif columnIndex == 2:
            return response_info.getStatusCode()
        elif columnIndex == 3:
            return len(messageInfo.getResponse())

    def isCellEditable(self, rowIndex, columnIndex):
        return False

class TableMouseListener(MouseAdapter):
    def __init__(self, extender):
        self._extender = extender

    def mouseClicked(self, event):
        row = self._extender._table.getSelectedRow()
        if row != -1:
            self._extender.display_request_response(row)
