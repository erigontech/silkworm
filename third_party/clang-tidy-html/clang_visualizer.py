import argparse
import logging
import re
import sys
from requests import Session
from requests.adapters import HTTPAdapter
from pathlib import Path
from bs4 import BeautifulSoup
import ssl
import certifi

log = logging.getLogger(__name__)
handler = logging.StreamHandler()
log_format = '%(asctime)s - %(name)12s - %(levelname)8s - %(message)s'
handler.setFormatter(logging.Formatter(log_format))
log.addHandler(handler)
log.setLevel(logging.DEBUG)

COLOR_DICT = {
    '0': [(88, 88, 88), (88, 88, 88)],
    '30': [(0, 0, 0), (0, 0, 0)],
    '31': [(255, 0, 0), (128, 0, 0)],
    '32': [(0, 255, 0), (0, 128, 0)],
    '33': [(255, 255, 0), (128, 128, 0)],
    '34': [(0, 0, 255), (0, 0, 128)],
    '35': [(255, 0, 255), (128, 0, 128)],
    '36': [(0, 255, 255), (0, 128, 128)],
    '37': [(255, 255, 255), (128, 128, 128)],
}

COLOR_REGEX = re.compile(
    r'\[(?P<arg_1>\d+)(;(?P<arg_2>\d+)(;(?P<arg_3>\d+))?)?m')

BOLD_TEMPLATE = '<span style="color: rgb{}; font-weight: bolder">'
LIGHT_TEMPLATE = '<span style="color: rgb{}">'


def ansi_to_html(text):
    text = text.replace('[0m', '</span>').replace('\033', '')

    def single_sub(match):
        argsdict = match.groupdict()
        bold = False
        color = '0'
        for arg in argsdict.values():
            if arg is not None:
                val = int(str(arg))
                if val == 0:
                    bold = False
                elif val == 1:
                    bold = True
                elif val >= 30 and val <= 37:
                    color = arg
        if bold:
            return BOLD_TEMPLATE.format(COLOR_DICT[color][1])
        return LIGHT_TEMPLATE.format(COLOR_DICT[color][0])

    return COLOR_REGEX.sub(single_sub, text)

# You can also import custom clang checks from checks.py below.
# from checks import checks_list

# Each check will have its own node of information.
class checks:
    def __init__(self, dataval=None):
        self.name = ''
        self.count = 0
        self.data = ''

# Begin here.
def main():
    # Process command line arguments.
    parser = argparse.ArgumentParser()
    parser.add_argument('file', type=Path)
    parser.add_argument(
        '-o', '--out', help="Generated html file name.", nargs='?', const="clang.html", default="clang.html", type=str)
    parser.add_argument(
        '-d', '--checks_dict_url', help="Override the latest checks list, (e.g., v14.0.0 uses \
        https://releases.llvm.org/14.0.0/tools/clang/tools/extra/docs/clang-tidy/checks/list.html).", nargs='?', type=str)

    try:
        args = parser.parse_args()
    except:
        parser.print_help()
        usage()
        sys.exit(-1)

    tidy_log_lines: Path = args.file
    output_path: Path = Path(args.out)
    clang_tidy_visualizer(tidy_log_lines, output_path, args.checks_dict_url)


def clang_tidy_visualizer(tidy_log_file: Path,
                          output_html_file: Path = Path("clang.html"),
                          checks_dict_url = None):
    tidy_log_lines = tidy_log_file.read_text().splitlines()
    clang_base_url = "https://clang.llvm.org/extra/clang-tidy/checks/"
    global checks_dict

    if checks_dict_url is None:
        checks_dict_url = clang_base_url + 'list.html'

    checks_dict = find_checks_dict(checks_dict_url)
    if checks_dict is None or len(checks_dict) == 0:
        print("Error! Could not retrieve a dictionary of checks.")
        exit(0)
    checks_list = list(checks_dict.keys())
    checks_list.sort()

    # Updates the newest clang-tidy checks to your checks.py file.
    write_checks_file(
        checks_list, to_file=output_html_file.parent / "clang-tidy-checks.py")

    checks_used = [0] * len(checks_list)

    # Increments each occurrence of a check.
    for line, content in enumerate(tidy_log_lines):
        content = content.replace('<', '&lt;')
        content = content.replace('>', '&gt;')
        for check_name in checks_list:
            if content.find(check_name.replace('/', '-')) != -1:
                checks_used[checks_list.index(check_name)] += 1

    # Counts the max number of used checks in the log file.
    num_used_checks = 0
    for line, check in enumerate(checks_list):
        if checks_used[line] != 0:
            num_used_checks += 1

    names_of_used = [None] * num_used_checks
    names_of_usedL = [None] * num_used_checks

    # Creates new check classes for each used check.
    used_line = 0
    total_num_checks = 0
    for line, check in enumerate(checks_list):
        if checks_used[line] != 0:
            new_node = checks(check)
            new_node.name = check
            new_node.count = checks_used[line]
            total_num_checks += checks_used[line]
            names_of_used[used_line] = new_node

            names_of_usedL[used_line] = checks_list[line]
            used_line += 1

    # Adds details for each organized check.
    for line, content in enumerate(tidy_log_lines):
        # Goes through each used check.
        for initial_check in names_of_usedL:
            # Adds the lines that detail the warning message.
            if content.find(initial_check.replace('/', '-')) != -1:
                content = content.replace('<', '&lt;')
                content = content.replace('>', '&gt;')
                names_of_used[names_of_usedL.index(
                    initial_check)].data += content + '\n'
                details = line + 1
                finished = False
                while not finished:
                    # Ensure there is no overflow.
                    if details >= len(tidy_log_lines):
                        break
                    # If the line includes a used Clang-Tidy check name,
                    # continue to find the next.
                    for end_check in names_of_usedL:
                        if tidy_log_lines[details].find(end_check.replace('/', '-')) != -1:
                            finished = True
                            break
                    # Otherwise, add the data to the specific used check
                    # name for the organization of checks in the HTML file.
                    if not finished:
                        names_of_used[names_of_usedL.index(
                            initial_check)].data += tidy_log_lines[details] + '\n'
                        details += 1

    with open(output_html_file, "w") as clang_html:
        log.info(f"Writing results to {output_html_file}")
        # Functions for writing to the clang.html file.
        writeHeader(clang_html)
        writeList(clang_html, num_used_checks, names_of_used,
                  clang_base_url, total_num_checks)
        writeSortedLogs(clang_html, tidy_log_lines,
                        num_used_checks, names_of_used, clang_base_url)
        writeScript(clang_html, num_used_checks)

# adapted from https://github.com/psf/requests/issues/4775#issuecomment-478198879
class TLSAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context(cafile=certifi.where())
        kwargs['ssl_context'] = ctx
        return super(TLSAdapter, self).init_poolmanager(*args, **kwargs)

# Scrape data from clang-tidy's official list of current checks.
def find_checks_dict(checks_dict_url: str):
    session = Session()
    session.mount('https://', TLSAdapter())
    try:
        res = session.get(checks_dict_url)
    except Exception as e:
        print(e)
        return None

    soup = BeautifulSoup(res.text, "lxml")
    scrape_checks_dict = dict()
    clang_check_links = soup.find_all('a', href=True)

    for link in clang_check_links:
        match_docs_check_name = re.match(
            "^([a-zA-Z0-9].*).html.*$", link['href'])
        if match_docs_check_name:
            docs_check_name = match_docs_check_name.group(1)
            split_docs_check = docs_check_name.split('/')
            len_split_docs_check = len(split_docs_check)
            if len_split_docs_check > 0 and len_split_docs_check <= 2:
                scrape_checks_dict[fromClangDocsName(
                    docs_check_name)] = split_docs_check[0]
    return scrape_checks_dict

# Optional: Update the checks.py file with the most recent checks.
def write_checks_file(checks_list, to_file):
    with open(to_file, 'w') as f:
        f.write('checks_list = [')
        for check, item in enumerate(checks_list):
            if check == len(checks_list) - 1:
                f.write("'{}']".format(item))
            else:
                f.write("'{}',".format(item))

# Helper functions to fix the links of the clang-tidy documentation.
# Referenced in #8
def toClangDocsName(original_check_name):
    checks_category = checks_dict[original_check_name]
    match_except_first_hyphen = re.compile(rf'^({checks_category})-(.*)$')
    clang_docs_name = match_except_first_hyphen.sub(
        r'\1/\2', original_check_name)
    return clang_docs_name

def fromClangDocsName(docs_check_name):
    return docs_check_name.replace('/', '-', 1)

# Prints usage information for the script.
def usage():
    print("""
***------------------------------------------ Clang HTML Visualizer -----------------------------------------***

    Generates an html file as a visual for clang-tidy checks. Additionally, it writes a checks.py file that
    informs you which checks have been scraped from http://clang.llvm.org/extra/clang-tidy/checks/list.html

    How to use:
    - Call the script directly:
        1. clang-tidy-html [logfile.log]
        2. python -m clang_html [logfile.log]
    OR
    - Import it in your Python terminal:
        >>> from pathlib import Path
        >>> from clang_html import clang_tidy_visualizer
        >>> clang_tidy_visualizer(Path("examples/sample.log"))

    Optional args:
    - [-o, --out] or clang_tidy_visualizer(path_to_log: Path, output_path: Path)
        - Rename the generated html file. The default filename is stored as "clang.html" in the directory
          from where you call the script.

***----------------------------------------------------------------------------------------------------------***""")

# Header of the clang.html file.
def writeHeader(f):
    f.write("""
<!DOCTYPE html>
<html>
<head>
	<title>Clang-Tidy Visualizer</title>
	<meta charset="UTF-8">
	<meta name="author" content="Austin Hale">
	<meta name="description" content="Documentation tool for visualizing Clang-Tidy checks.">
	<meta name="viewport" content="width=device-width,initial-scale=1">
	<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
	<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>
	<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
</head>
""")

# List the used checks found in the source code.
def writeList(f, num_used_checks, names_of_used, clang_base_url, total_num_checks):
    f.write("""
<body style="background: rgb(220, 227, 230); width: 100%; height: 100%;">
    <div id="container" style="margin-left: 2%; margin-right: 2%;">
	    <div id="header" style="height: 55px; display: flex; justify-content: left; position: relative;">
		    <h3 style="text-align: center; color: #111; font-family: 'Helvetica Neue', sans-serif; font-weight: bold;     letter-spacing: 0.5px; line-height: 1;">Clang-Tidy Checks</h3>
		    <div class="btn-group" role="group" style="position: absolute; right: 0;">
			    <button type="button" class="btn btn-warning" onclick="highlightChecks(0)" style="outline: none; color: black">Warning</button>
			    <button type="button" class="btn btn-danger" onclick="highlightChecks(1)" style="outline: none; color: black">Danger</button>
			    <button type="button" class="btn btn-info" onclick="clearChecks()" style="outline: none; color: black">Clear All</button>
		    </div>
	    </div>
        <br>
	    <ul id="list" class="list-group" align="left" style="display: block; width: 25%; height: 0; margin-bottom: 0;">
""")

    # Iterates through each used check's details and organizes them into the given <pre> sections.
    f.write("""
            <a id=\"log\" href=\"#\" class=\"list-group-item list-group-item-success\" style=\"color: black; font-weight: bold; letter-spacing:0.4px;\"onclick=\"toggleLog()\">
                {} Original Log
            </a>
""".format(total_num_checks))

    for line in range(0, num_used_checks):
        f.write("""
            <a id=\"check{0}\" style=\"color: black\" href=\"#\" class=\"list-group-item list-group-item-action\"onclick=\"toggleInfo({0})\">
                {1} {2}
            </a>
""".format(line, names_of_used[line].count, names_of_used[line].name.replace('/', '-')))

    f.write("""
        </ul>

        <div id="showLog" style="display: none; width: 75%; float: right;">
            <div style="display: flex; justify-content: left; position: relative;">
                <button id="collapse-btn0" type="button" class="btn nohover" onclick="collapseSidebar()" style="outline: none; background-color: lightgray" title="Collapse sidebar">
                <span id="collapse-img0" class="glyphicon glyphicon-menu-left"></button></span>
                <h4 style="margin-top: 0; color: #111; position: absolute; left: 50%; transform: translateX(-50%); margin-bottom: 10;">Original Log</h4>
""")

    # Attach a button to the list of all checks in clang. Link opens in a new tab.
    clang_check_url = clang_base_url.replace('/', '\/') + 'list.html'
    external_name = 'Clang-Tidy Checks'
    f.write("""
                <button id=\"externalLink\" type=\"button\" class=\"btn\" onclick=\"window.open('{}','_blank')\"
                            style=\"outline: none; position: absolute; color: #111; right: 0; background-color: rgb(181, 215, 247)\">
                    {}
                    <span class=\"glyphicon glyphicon-new-window\">
                </button></span>
""".format(clang_check_url, external_name))

    f.write("""
            </div>
            <pre>
""")

# Sort through the used check logs for outputting the html.
def writeSortedLogs(f, tidy_log_lines, num_used_checks, names_of_used, clang_base_url):
    for line in tidy_log_lines:
        line = line.replace('<', '&lt;')
        line = line.replace('>', '&gt;')
        f.write("{}\n".format(line))

    f.write("""
            </pre>
        </div>
""")

    for check_idx in range(0, num_used_checks):
        collapse_idx = check_idx + 1
        f.write("""
        <div id=\"show{0}\" style=\"display: none; width: 75%; float: right\">
            <div style=\"display: flex; justify-content: left; position: relative;\">
                <button id=\"collapse-btn{1}\" type=\"button\" class=\"btn nohover\" onclick=\"collapseSidebar()\"
                            style=\"outline: none; background-color: lightgray\" title=\"Collapse sidebar\">
                <span id=\"collapse-img{1}\" class=\"glyphicon glyphicon-menu-left\"></button></span>
                <h4 style=\"margin-top: 0; color: #111; position: absolute; left: 50%; transform: translateX(-50%); margin-bottom: 10px;\">
                    {2}
                </h4>
""".format(check_idx, collapse_idx, names_of_used[check_idx].name))

        # Attach a button to the specific check's docs in clang. Link opens in a new tab.
        docs_check_name = toClangDocsName(names_of_used[check_idx].name)
        clang_check_url = clang_base_url.replace(
            '/', '\/') + docs_check_name + '.html'
        external_name = 'Documentation'
        f.write("""
                    <button id=\"externalLink\" type=\"button\" class=\"btn\" onclick=\"window.open('{}','_blank')\"
                                style=\"outline: none; position: absolute; color: #111; right: 0; background-color: rgb(181, 215, 247)\">
                        {}
                        <span class=\"glyphicon glyphicon-new-window\">
                    </button></span>
    """.format(clang_check_url, external_name))

        f.write("""
            </div>
            <pre>
""")

        names_of_used[check_idx].data = names_of_used[check_idx].data.replace(
            '<', '&lt;')
        names_of_used[check_idx].data = names_of_used[check_idx].data.replace(
            '>', '&gt;')
        names_of_used[check_idx].data = ansi_to_html(
            names_of_used[check_idx].data)
        f.write("""{}
            </pre>
        </div>
""".format(names_of_used[check_idx].data))

    f.write("""
    </div>
</body>
""")

# Writes Javascript and JQuery code to the html file for button and grouping functionalities.
def writeScript(f, num_used_checks):
    f.write("""
<script>
	var selected_idx;
	var checks_arr = [];
	var highlights = 'highlights';
	// Retrieves local storage data on document load for highlighted checks.
	$(document).ready(function () {{
        let stored_highlights = localStorage.getItem(highlights);
		for (let all_checks = 0; all_checks < {0}; all_checks++) {{
			let check_hl = document.getElementById("check" + all_checks);
            let no_previous_state = false;
            if (stored_highlights !== null) {{
                switch (JSON.parse(stored_highlights)[all_checks]) {{
                    case "warning":
                        check_hl.classList.add('list-group-item-warning');
                        checks_arr[all_checks] = "warning";
                        break;
                    case "danger":
                        check_hl.classList.add('list-group-item-danger');
                        checks_arr[all_checks] = "danger";
                        break;
                    default:
                        no_previous_state = true;
                        break;
                }}
            }}

            if (stored_highlights === null || no_previous_state) {{
                checks_arr[all_checks] = "action";
                check_hl.classList.add('list-group-item-action');
            }}
		}}
		localStorage.setItem(highlights, JSON.stringify(checks_arr));
	}});

	function toggleLog() {{
		let log = document.getElementById("showLog");
		clearContent();
        log.style.display = (log.style.display === "none") ? "block" : "none";
		selected_idx = undefined;
	}}

	function toggleInfo(check_position) {{
		selected_idx = check_position;
		clearContent();
		// Displays the chosen clang-tidy category.
		let category = document.getElementById("show" + check_position);
        category.style.display = (category.style.display === "none") ? "block" : "none";
	}}

	// Clears document when choosing another selection.
	function clearContent() {{
		for (let all_checks = 0; all_checks < {0}; all_checks++) {{
			let clear = document.getElementById("show" + all_checks);
			if (clear.style.display === "block") {{
				clear.style.display = "none";
			}}
		}}
		let clearLog = document.getElementById("showLog");
		if (clearLog.style.display === "block") {{
			clearLog.style.display = "none";
		}}
	}}

	// Type 1 used for highlighting danger checks and 0 for warnings.
	function highlightChecks(type) {{
		if (selected_idx === undefined) return;
		let check_hl = document.getElementById("check" + selected_idx);
		if (check_hl !== null) {{
			if (check_hl.classList.contains('list-group-item-warning')) {{
				check_hl.classList.remove('list-group-item-warning');
                if (type == 1) {{
                    check_hl.classList.add('list-group-item-danger');
                    checks_arr[selected_idx] = "danger";
                }} else {{
                    check_hl.classList.add('list-group-item-action');
                    checks_arr[selected_idx] = "action"
                }}
			}} else if (check_hl.classList.contains('list-group-item-danger')) {{
				check_hl.classList.remove('list-group-item-danger');
                if (type == 1) {{
                    check_hl.classList.add('list-group-item-action');
                    checks_arr[selected_idx] = "action";
                }} else {{
                    check_hl.classList.add('list-group-item-warning');
                    checks_arr[selected_idx] = "warning";
                }}
			}} else if (check_hl.classList.contains('list-group-item-action')) {{
				check_hl.classList.remove('list-group-item-action');
                if (type == 1) {{
                    check_hl.classList.add('list-group-item-danger');
                    checks_arr[selected_idx] = "danger";
                }} else {{
                    check_hl.classList.add('list-group-item-warning');
                    checks_arr[selected_idx] = "warning";
                }}
			}}
		}}
		// Sets local storage for each occurrence of a highlighted check.
		localStorage.setItem(highlights, JSON.stringify(checks_arr));
	}}

	function clearChecks(type) {{
		for (let all_checks = 0; all_checks < {0}; all_checks++) {{
			let clear = (document.getElementById("check" + all_checks));
			checks_arr[all_checks] = "action";
			if (clear !== null) {{
				if (clear.classList.contains('list-group-item-warning')) {{
					clear.classList.remove('list-group-item-warning');
				}} else if (clear.classList.contains('list-group-item-danger')) {{
					clear.classList.remove('list-group-item-danger');
				}}
				clear.classList.add('list-group-item-action');
			}}
		}}
		// Restores all checks to unhighlighted state on local storage.
		localStorage.removeItem(highlights);
	}}

	function collapseSidebar() {{
		let list = document.getElementById("list"); let hasExpanded;
		let log_details = document.getElementById("showLog");
		list.style.display === "block" ? hasSidebar = true : hasSidebar = false;
		hasSidebar ? list.style.display = "none" : list.style.display = "block";
		for (let all_checks = 0; all_checks <= {0}; all_checks++) {{
			let collapse_img = document.getElementById("collapse-img" + all_checks);
			let collapse_btn = document.getElementById("collapse-btn" + all_checks);
			let check_details = document.getElementById("show" + all_checks);
			if (collapse_img !== null) {{
                if (hasSidebar) {{
                    collapse_img.classList.remove('glyphicon-menu-left');
                    collapse_img.classList.add('glyphicon-menu-right');
                    collapse_btn.title = "Expand sidebar";
                }}
                else {{
                    collapse_img.classList.remove('glyphicon-menu-right');
                    collapse_img.classList.add('glyphicon-menu-left');
                    collapse_btn.title = "Collapse sidebar";
                }}
			}}
			if (check_details !== null) {{ check_details.style.width = hasSidebar ? "100%" : "75%"; }}
		}}
		log_details.style.width = hasSidebar ? "100%" : "75%";
	}}
</script>
<style>
	pre {{
		white-space: pre-wrap;
		word-break: keep-all;
	}}

	#header {{
		border-bottom: 2px solid darkgray
	}}
</style>

</html>
""".format(num_used_checks))
