use crate::{
    time::{Duration, Stopwatch},
    ui::{
        component::{Component, Event, EventCtx, Timeout},
        constant::screen,
        display::{Color, Icon},
        geometry::{Alignment2D, Insets, Rect},
        lerp::Lerp,
        shape,
        shape::Renderer,
    },
};

use super::{theme, Swipe, SwipeDirection};

const TIMEOUT_MS: u32 = 2000;

#[derive(Default, Clone)]
struct StatusAnimation {
    pub timer: Stopwatch,
}

impl StatusAnimation {
    const DURATION: f32 = TIMEOUT_MS as f32 / 1000.0;

    pub fn is_active(&self) -> bool {
        self.timer.is_running_within(Duration::from(Self::DURATION))
    }

    pub fn eval(&self) -> (u8, u8, i16) {
        let instruction_opacity = pareen::constant(0.0).seq_ease_in_out(
            0.0,
            easer::functions::Cubic,
            0.42,
            pareen::constant(1.0),
        );

        let content_opacity = pareen::constant(0.0).seq_ease_in_out(
            0.18,
            easer::functions::Cubic,
            0.2,
            pareen::constant(1.0),
        );

        let circle_scale = pareen::constant(0.0).seq_ease_out(
            0.2,
            easer::functions::Cubic,
            0.4,
            pareen::constant(1.0),
        );

        let t = self.timer.elapsed().into();

        let o1 = instruction_opacity.eval(t);
        let o1: u8 = u8::lerp(0, 255, o1);
        let o2 = content_opacity.eval(t);
        let o2: u8 = u8::lerp(0, 255, o2);

        let s1 = i16::lerp(170 / 2, 80 / 2, circle_scale.eval(t));

        (o1, o2, s1)
    }

    pub fn start(&mut self) {
        self.timer.start();
    }

    pub fn reset(&mut self) {
        self.timer = Stopwatch::new_stopped();
    }
}

/// Component showing status of an operation. Most typically embedded as a
/// content of a Frame and showing success (checkmark with a circle around).
#[derive(Clone)]
pub struct StatusScreen {
    area: Rect,
    icon: Icon,
    icon_color: Color,
    circle_color: Color,
    dismiss_type: DismissType,
    anim: StatusAnimation,
}

#[derive(Clone)]
enum DismissType {
    SwipeUp(Swipe),
    Timeout(Timeout),
}

impl StatusScreen {
    fn new(icon: Icon, icon_color: Color, circle_color: Color, dismiss_style: DismissType) -> Self {
        Self {
            area: Rect::zero(),
            icon,
            icon_color,
            circle_color,
            dismiss_type: dismiss_style,
            anim: StatusAnimation::default(),
        }
    }

    pub fn new_success() -> Self {
        Self::new(
            theme::ICON_SIMPLE_CHECKMARK,
            theme::GREEN_LIME,
            theme::GREEN_LIGHT,
            DismissType::SwipeUp(Swipe::new().up()),
        )
    }

    pub fn new_success_timeout() -> Self {
        Self::new(
            theme::ICON_SIMPLE_CHECKMARK,
            theme::GREEN_LIME,
            theme::GREEN_LIGHT,
            DismissType::Timeout(Timeout::new(TIMEOUT_MS)),
        )
    }

    pub fn new_neutral() -> Self {
        Self::new(
            theme::ICON_SIMPLE_CHECKMARK,
            theme::GREY_EXTRA_LIGHT,
            theme::GREY_DARK,
            DismissType::SwipeUp(Swipe::new().up()),
        )
    }

    pub fn new_neutral_timeout() -> Self {
        Self::new(
            theme::ICON_SIMPLE_CHECKMARK,
            theme::GREY_EXTRA_LIGHT,
            theme::GREY_DARK,
            DismissType::Timeout(Timeout::new(TIMEOUT_MS)),
        )
    }
}

impl Component for StatusScreen {
    type Msg = ();

    fn place(&mut self, bounds: Rect) -> Rect {
        self.area = bounds;
        if let DismissType::SwipeUp(swipe) = &mut self.dismiss_type {
            swipe.place(bounds);
        }
        bounds
    }

    fn event(&mut self, ctx: &mut EventCtx, event: Event) -> Option<Self::Msg> {
        if let Event::Attach = event {
            self.anim.start();
            ctx.request_paint();
            ctx.request_anim_frame();
        }
        if self.anim.is_active() {
            ctx.request_anim_frame();
            ctx.request_paint();
        }

        match self.dismiss_type {
            DismissType::SwipeUp(ref mut swipe) => {
                let swipe_dir = swipe.event(ctx, event);
                if let Some(SwipeDirection::Up) = swipe_dir {
                    return Some(());
                }
            }
            DismissType::Timeout(ref mut timeout) => {
                if timeout.event(ctx, event).is_some() {
                    return Some(());
                }
            }
        }

        None
    }

    fn paint(&mut self) {
        todo!()
    }

    fn render<'s>(&'s self, target: &mut impl Renderer<'s>) {
        let (o1, o2, s1) = self.anim.eval();

        shape::Circle::new(self.area.center(), s1)
            .with_fg(self.circle_color)
            .with_bg(theme::BLACK)
            .with_thickness(2)
            .render(target);
        shape::ToifImage::new(self.area.center(), self.icon.toif)
            .with_align(Alignment2D::CENTER)
            .with_fg(self.icon_color)
            .render(target);

        //content + header cover
        shape::Bar::new(self.area.outset(Insets::top(self.area.y0)))
            .with_fg(theme::BLACK)
            .with_bg(theme::BLACK)
            .with_alpha(255 - o2)
            .render(target);

        //instruction cover
        shape::Bar::new(screen().inset(Insets::top(self.area.y1)))
            .with_fg(theme::BLACK)
            .with_bg(theme::BLACK)
            .with_alpha(255 - o1)
            .render(target);
    }
}

#[cfg(feature = "ui_debug")]
impl crate::trace::Trace for StatusScreen {
    fn trace(&self, t: &mut dyn crate::trace::Tracer) {
        t.component("StatusScreen");
    }
}
