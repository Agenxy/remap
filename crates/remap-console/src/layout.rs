// SPDX-License-Identifier: GPL-3.0-or-later
//! Where each part of the screen goes. Shared by the view and by paging so
//! both agree on how many rows the table has.

use ratatui::layout::Rect;

use crate::model::Model;
use crate::text;

/// From this width the detail pane sits beside the table.
const SIDE_DETAIL_MIN_WIDTH: u16 = 110;
const SIDE_DETAIL_WIDTH: u16 = 44;
/// The detail pane below the table needs this much main height.
const BELOW_DETAIL_MIN_MAIN: u16 = 14;
pub(crate) const BELOW_DETAIL_HEIGHT: u16 = 6;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct Regions {
    pub(crate) header: Rect,
    pub(crate) problems: Rect,
    pub(crate) problem_lines: Vec<String>,
    pub(crate) table: Rect,
    pub(crate) detail: Option<Rect>,
    pub(crate) beside: bool,
    pub(crate) notice: Rect,
    pub(crate) footer: Rect,
}

impl Regions {
    /// Mapping rows below the table's title and column header.
    pub(crate) fn table_rows(&self) -> usize {
        usize::from(self.table.height.saturating_sub(2))
    }
}

pub(crate) fn regions(model: &Model, area: Rect) -> Regions {
    let height = area.height;
    let header_height = height.min(1);
    let footer_height = (height - header_height).min(1);
    let notice_height = (height - header_height - footer_height).min(1);
    let rest = height - header_height - footer_height - notice_height;
    let mut problem_lines: Vec<String> = text::problems(model)
        .iter()
        .flat_map(|problem| text::wrap(problem, usize::from(area.width)))
        .collect();
    let most = if rest >= 8 { rest / 3 } else { rest.min(1) };
    problem_lines.truncate(usize::from(most));
    let problem_height = u16::try_from(problem_lines.len()).unwrap_or(most);
    let main_height = rest - problem_height;
    let row = |y: u16, rows: u16| Rect::new(area.x, y, area.width, rows);
    let header = row(area.y, header_height);
    let problems = row(header.bottom(), problem_height);
    let main = row(problems.bottom(), main_height);
    let notice = row(main.bottom(), notice_height);
    let footer = row(notice.bottom(), footer_height);
    let (table, detail, beside) = split_main(main);
    Regions {
        header,
        problems,
        problem_lines,
        table,
        detail,
        beside,
        notice,
        footer,
    }
}

fn split_main(main: Rect) -> (Rect, Option<Rect>, bool) {
    if main.width >= SIDE_DETAIL_MIN_WIDTH {
        let table = Rect::new(main.x, main.y, main.width - SIDE_DETAIL_WIDTH, main.height);
        let detail = Rect::new(table.right(), main.y, SIDE_DETAIL_WIDTH, main.height);
        return (table, Some(detail), true);
    }
    if main.height >= BELOW_DETAIL_MIN_MAIN {
        let table_height = main.height - BELOW_DETAIL_HEIGHT;
        let table = Rect::new(main.x, main.y, main.width, table_height);
        let detail = Rect::new(main.x, table.bottom(), main.width, BELOW_DETAIL_HEIGHT);
        return (table, Some(detail), false);
    }
    (main, None, false)
}
