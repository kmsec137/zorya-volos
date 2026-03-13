use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, Paragraph, Row, Table},
    Frame, Terminal,
};
use std::{error::Error, io, time::{Duration, Instant}};

// --- State Management ---
struct App {
    logs: Vec<String>,
    // Memory map now stores (Total Hits, Last Interaction Type)
    memory_map: Vec<(u64, InteractionType)>,
    stats: Stats,
}

#[derive(Clone, Copy, PartialEq)]
enum InteractionType { None, Read, Write }

struct Stats {
    block_count: u64,
    stack_depth: u32,
    run_time: Duration,
    mem_writes: u64,
    mem_reads: u64,
}

fn main() -> Result<(), Box<dyn Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App {
        logs: vec!["[SYS] Zorya-Volos Kernel Hook Active".into()],
        memory_map: vec![(0, InteractionType::None); 30],
        stats: Stats {
            block_count: 0,
            stack_depth: 0,
            run_time: Duration::default(),
            mem_writes: 0,
            mem_reads: 0,
        },
    };

    let start_time = Instant::now();
    loop {
        terminal.draw(|f| ui(f, &app))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if let KeyCode::Char('q') = key.code { break; }
            }
        }

        // Simulate logic
        app.stats.run_time = start_time.elapsed();
        update_simulation(&mut app);
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    Ok(())
}

fn update_simulation(app: &mut App) {
    let mut rng = rand::rng();
    app.stats.block_count += 1;
    
    // Random interaction
    let idx = (rand::random::<u32>() as usize) % app.memory_map.len();
    let is_write = rand::random::<bool>();
    
    if is_write {
        app.stats.mem_writes += 1;
        app.memory_map[idx] = (app.memory_map[idx].0 + 1, InteractionType::Write);
    } else {
        app.stats.mem_reads += 1;
        app.memory_map[idx] = (app.memory_map[idx].0 + 1, InteractionType::Read);
    }

    if app.stats.block_count % 50 == 0 {
        app.logs.push(format!("[TRACE] Syscall at 0x{:08X}", rand::random::<u32>()));
    }
}

fn ui(f: &mut Frame, app: &App) {
    // 1. Split Screen into Top Half and Bottom Half (50/50)
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(f.size());

    // 2. Split Top Half (2/3 Stats, 1/3 Memory Map)
    let top_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(66), Constraint::Percentage(34)])
        .split(main_layout[0]);

    // --- PANE 1: Stats (Top Left) ---
	 let blocks = &app.stats.block_count.to_string();
	 let stack_depth = &app.stats.stack_depth.to_string();
	 let mem_reads = &app.stats.mem_reads.to_string();
	 let mem_writes = &app.stats.mem_writes.to_string();
    let stats_rows = vec![
        //Row::new(vec!["Runtime:", format!("{:?}", app.stats.run_time.to_string())]),
        Row::new(vec!["Blocks Executed:", blocks]),
        Row::new(vec!["Stack Depth:", stack_depth]),
        Row::new(vec!["Mem Reads:", mem_reads]),
        Row::new(vec!["Mem Writes:", mem_writes]),
    ];
    let stats_table = Table::new(stats_rows, [Constraint::Length(20), Constraint::Min(10)])
        .block(Block::default().title(" EXECUTION METRICS ").borders(Borders::ALL))
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(stats_table, top_layout[0]);

    // --- PANE 2: Memory Heatmap (Top Right) ---
    let mem_items: Vec<ListItem> = app.memory_map.iter().enumerate().map(|(i, (hits, kind))| {
        let addr = i as u64 * (0xFFFFFFFF / app.memory_map.len() as u64);
        let type_tag = match kind {
            InteractionType::Read => " (R)",
            InteractionType::Write => " (W)",
            _ => "    ",
        };
        let color = if *hits > 20 { Color::Red } else if *hits > 0 { Color::Yellow } else { Color::DarkGray };
        
        ListItem::new(format!("0x{:08X} [{:03}]{}", addr, hits, type_tag))
            .style(Style::default().fg(color))
    }).collect();
    
    let mem_list = List::new(mem_items)
        .block(Block::default().title(" MEM HEATMAP ").borders(Borders::ALL));
    f.render_widget(mem_list, top_layout[1]);

    // --- PANE 3: Log Scroller (Bottom Half) ---
    let log_height = main_layout[1].height as usize;
    // Get last N logs, and reverse to show "scrolling up"
    let logs: Vec<ListItem> = app.logs.iter().rev().take(log_height - 3)
        .map(|msg| ListItem::new(msg.as_str())).collect();
    
    let log_block = List::new(logs)
        .block(Block::default().title(" TRACE LOG ").borders(Borders::ALL))
        .style(Style::default().fg(Color::White));
    f.render_widget(log_block, main_layout[1]);
}
