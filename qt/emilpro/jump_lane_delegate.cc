#include "jump_lane_delegate.hh"

#include <qpainter.h>

using namespace emilpro;

constexpr auto kNumberOfLanes = JumpLanes::kNumberOfLanes;

JumpLaneDelegate::JumpLaneDelegate(Direction direction, QObject* parent)
    : m_direction(direction)
    , m_lane_width(80 / kNumberOfLanes)
{
}

void
JumpLaneDelegate::Update(
    unsigned max_distance,
    std::span<const std::reference_wrapper<emilpro::IInstruction>> instructions)
{
    m_jump_lanes.Calculate(max_distance, instructions);
}

QSize
JumpLaneDelegate::sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const
{
    QRect r = option.rect;

    return QSize(80, r.height());
}

void
JumpLaneDelegate::paint(QPainter* painter,
                        const QStyleOptionViewItem& option,
                        const QModelIndex& index) const
{
    const auto color = std::array {
        QColor {Qt::green},
        QColor {Qt::cyan},
        QColor {Qt::red},
        QColor {Qt::magenta},
    };

    int row = index.row();
    QRect r = option.rect;

    auto lanes = m_jump_lanes.GetLanes()[row];

    for (unsigned lane = 0; lane < kNumberOfLanes; lane++)
    {
        const auto& cur = m_direction == Direction::kForward ? lanes.forward_lanes[lane]
                                                             : lanes.backward_lanes[lane];
        auto x = r.x() + m_lane_width * lane;
        auto w = r.width() / kNumberOfLanes;

        QPen pen(color[lane], Qt::SolidLine);
        pen.setWidth(2);

        painter->setPen(pen);
        painter->setBrush(QBrush(color[lane]));

        using Type = JumpLanes::Type;
        switch (cur)
        {
        case Type::kTraffic:
            DrawLine(painter, x, w, &r);
            break;
        case Type::kEnd:
            DrawLineEnd(painter, m_direction, x, w, &r);
            break;
            //        case JumpTargetDisplay::LANE_END_UP:
            //            DrawLineEnd(painter, true, x, w, &r);
            //            break;
        case Type::kStart:
            DrawLineStart(painter, m_direction, x, w, &r);
            break;
            //        case JumpTargetDisplay::LANE_START_UP:
            //            DrawLineStart(painter, true, x, w, &r);
            //            break;
            //        case JumpTargetDisplay::LANE_START_LONG_DOWN:
            //            pen.setStyle(Qt::DotLine);
            //            painter->setPen(pen);
            //            DrawLineStart(painter, m_direction, x, w, &r);
            //            break;
            //        case JumpTargetDisplay::LANE_START_LONG_UP:
            //            pen.setStyle(Qt::DotLine);
            //            painter->setPen(pen);
            //            DrawLineStart(painter, true, x, w, &r);
            //            break;
            //        case JumpTargetDisplay::LANE_END_LONG_DOWN:
            //            pen.setStyle(Qt::DotLine);
            //            painter->setPen(pen);
            //            DrawLineEnd(painter, m_direction, x, w, &r);
            //            break;
            //        case JumpTargetDisplay::LANE_END_LONG_UP:
            //            pen.setStyle(Qt::DotLine);
            //            painter->setPen(pen);
            //            DrawLineEnd(painter, true, x, w, &r);
            //            break;
        default:
            break;
        }
    }
}

void
JumpLaneDelegate::DrawLine(QPainter* painter, int x, int w, QRect* rect) const
{
    painter->drawLine(x + w / 2, rect->y(), x + w / 2, rect->y() + rect->height());
}

void
JumpLaneDelegate::DrawLineStart(
    QPainter* painter, Direction direction, int x, int w, QRect* rect) const
{
    const auto startY = rect->y() + rect->height() / 2;
    const auto endY = direction == Direction::kBackward ? rect->y() : rect->y() + rect->height();
    const auto startX = x + w / 2;

    painter->drawEllipse(startX - 3, startY - 3, 6, 6);
    painter->drawLine(startX, startY, startX, endY);
}

void
JumpLaneDelegate::DrawLineEnd(
    QPainter* painter, Direction direction, int x, int w, QRect* rect) const
{
    const auto endY = rect->y() + rect->height() / 2;
    const auto startY = direction == Direction::kBackward ? rect->y() + rect->height() : rect->y();
    const auto startX = x + w / 2;
    const auto endX = direction == Direction::kBackward ? rect->x() + rect->width() : rect->x();
    const auto arrowDir = direction == Direction::kBackward ? -1 : 1;
    QPolygon polygon;

    painter->drawLine(startX, startY, startX, endY);

    polygon << QPoint(startX, endY) << QPoint(endX, endY) << QPoint(endX + 5 * arrowDir, endY - 5)
            << QPoint(endX + 5 * arrowDir, endY + 5) << QPoint(endX, endY);

    painter->drawPolygon(polygon);
}
