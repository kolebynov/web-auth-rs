use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures::{Future, TryFuture};
use pin_project::pin_project;

enum SelectSeqState {
    PollFirst,
    PollSecond,
}

#[pin_project]
pub struct SelectSeqOk<Fut1, Fut2> {
    #[pin]
    fut1: Fut1,
    #[pin]
    fut2: Fut2,
    state: SelectSeqState,
}

impl<Fut1, Fut2> Future for SelectSeqOk<Fut1, Fut2>
where
    Fut1: TryFuture<Ok = Fut2::Ok, Error = Fut2::Error>,
    Fut2: TryFuture,
{
    type Output = Result<Fut1::Ok, Fut1::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.state {
            SelectSeqState::PollFirst => match this.fut1.try_poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(result) => {
                    if result.is_ok() {
                        Poll::Ready(result)
                    } else {
                        *this.state = SelectSeqState::PollSecond;
                        this.fut2.try_poll(cx)
                    }
                }
            },
            SelectSeqState::PollSecond => this.fut2.try_poll(cx),
        }
    }
}

#[pin_project]
pub struct SelectSeqSome<Fut1, Fut2> {
    #[pin]
    fut1: Fut1,
    #[pin]
    fut2: Fut2,
    state: SelectSeqState,
}

impl<T, Fut1, Fut2> Future for SelectSeqSome<Fut1, Fut2>
where
    Fut1: Future<Output = Option<T>>,
    Fut2: Future<Output = Option<T>>,
{
    type Output = Option<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.state {
            SelectSeqState::PollFirst => match this.fut1.poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(result) => {
                    if result.is_some() {
                        Poll::Ready(result)
                    } else {
                        *this.state = SelectSeqState::PollSecond;
                        this.fut2.poll(cx)
                    }
                }
            },
            SelectSeqState::PollSecond => this.fut2.poll(cx),
        }
    }
}

pub fn select_seq_ok<Fut1, Fut2>(fut1: Fut1, fut2: Fut2) -> SelectSeqOk<Fut1, Fut2>
where
    Fut1: TryFuture<Ok = Fut2::Ok, Error = Fut2::Error>,
    Fut2: TryFuture,
{
    SelectSeqOk {
        fut1,
        fut2,
        state: SelectSeqState::PollFirst,
    }
}

pub fn select_seq_some<T, Fut1, Fut2>(fut1: Fut1, fut2: Fut2) -> SelectSeqSome<Fut1, Fut2>
where
    Fut1: Future<Output = Option<T>>,
    Fut2: Future<Output = Option<T>>,
{
    SelectSeqSome {
        fut1,
        fut2,
        state: SelectSeqState::PollFirst,
    }
}
