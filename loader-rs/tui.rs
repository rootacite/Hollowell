use std::cmp::min;

use crate::stagger::debug::HollowDebug;

use anyhow::Result;
use crossterm::{
    execute,
    terminal::{EnterAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use hollowell::asm::DynamicFormatter;

use ratatui::widgets::{List, ListDirection};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    prelude::*,
    style::{Modifier, Style},
    text::{Line},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
};
use std::io;
use std::io::Stdout;

pub struct UI {
    pub terminal: Terminal<CrosstermBackend<Stdout>>,
    pub table_state: TableState,
}

impl UI {
    pub fn new() -> Result<Self> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;

        let backend = CrosstermBackend::new(io::stdout());
        let terminal = Terminal::new(backend)?;

        let mut table_state = TableState::default();
        table_state.select(Some(0));

        Ok(UI { terminal, table_state })
    }

    pub fn flush(&mut self, hd: &mut HollowDebug) -> Result<()> {
        if hd.clear {
            self.terminal.clear()?;
            hd.clear = false;
        }

        if let Some(major) = &hd.major {
            self.terminal.draw(|f| {
                let size = f.area();
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(25), Constraint::Length(12)])
                    .split(size);

                let header_cells = [
                    format!("Origin ({})", major.map.format_address(hd.focused_origin[0].ip() as usize)),
                    format!("Relocated ({})", major.map.format_address(hd.focused_relocated[0].ip() as usize)),
                ].into_iter().map(|h| {
                    Cell::from(Line::from((*h).to_string()))
                        .style(Style::default().add_modifier(Modifier::BOLD))
                });
                let header = Row::new(header_cells).height(1);

                let t1 = hd.focused_origin
                    .iter()
                    .map(|x| x.format_tui(hd.ips.0, &major.map))
                    .collect::<Vec<_>>();

                let t2 = hd.focused_relocated
                    .iter()
                    .map(|x| x.format_tui(hd.ips.1, &major.map))
                    .collect::<Vec<_>>();

                let widths = [
                    Constraint::Fill(1),
                    Constraint::Fill(1),
                ];
                let mut rows = Vec::new();
                for i in 0..min(t1.len(), t2.len()) {
                    rows.push(Row::new(vec![t1[i].clone(), t2[i].clone()]));
                }

                let asm_block = Block::default()
                    .borders(Borders::ALL)
                    .title("Assembly");

                let table = Table::new(rows, widths)
                    .header(header)
                    .block(asm_block)
                    .column_spacing(1);

                f.render_stateful_widget(table, chunks[0], &mut self.table_state);

                let list = List::new(hd.focused_near.iter().map(|x| x.format_tui(major.getip().unwrap_or(0), &major.map)).collect::<Vec<_>>())
                    .block(Block::bordered().title("Messages"))
                    .style(Style::new().white())
                    .highlight_style(Style::new().italic())

                    .highlight_symbol(">>")
                    .repeat_highlight_symbol(true)
                    .direction(ListDirection::TopToBottom);

                f.render_widget(list, chunks[1]);

                self.table_state.select(Some(hd.ins_number));
            })?;
        }

        Ok(())
    }

    pub fn clean(&mut self) {
        disable_raw_mode().unwrap();
    }
}

impl Drop for UI {
    fn drop(&mut self) {
        self.clean();
    }
}
