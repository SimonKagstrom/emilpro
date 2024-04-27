#pragma once

#include "emilpro/jump_lanes.hh"

#include <qitemdelegate.h>

class JumpLaneDelegate : public QItemDelegate
{
    Q_OBJECT

public:
    enum class Direction
    {
        kForward,
        kBackward,
    };

    JumpLaneDelegate(Direction direction, QObject* parent = 0);

    void Update(unsigned max_distance,
                std::span<const std::reference_wrapper<emilpro::IInstruction>> instructions);

private:
    void paint(QPainter* painter,
               const QStyleOptionViewItem& option,
               const QModelIndex& index) const final;

    QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const final;

    void DrawLine(QPainter* painter, int x, int w, QRect* rect) const;

    void DrawLineStart(QPainter* painter, Direction direction, int x, int w, QRect* rect) const;

    void DrawLineEnd(QPainter* painter, Direction direction, int x, int w, QRect* rect) const;

    const Direction m_direction;
    const unsigned int m_lane_width;
    emilpro::JumpLanes m_jump_lanes;
};
