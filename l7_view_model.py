"""The two-level L7 v2 model (docs/L7V2_DESIGN.md 8.1, D-V5): a view encoder and a GRU over the last page views.

Level 1 is the view token (l7_features.token_matrix: one row per complete view, the hand-built aggregates of design
8.1) passed through a learned encoder, one linear layer and a ReLU shared by every time step. Level 2 is a GRU over the
encoded tokens; the classifier reads its last step, where the most recent complete view sits. The encoder adds no
information the token summaries of the HGB and the LR lack (design 8.2); a GRU win has to come from order.

Padding tokens (column 0, `valid`, = 0) are zero after l7_features.apply_scaling, and the encoder's output is masked
with `valid`, so they stay exactly zero inside the model too: a window's score does not depend on what padding holds.
"""
from torch import nn


class ViewGRU(nn.Module):
    def __init__(self, input_size, embed_size=32, hidden_size=64, num_layers=2, dropout_rate=0.2):
        super().__init__()
        self.embed_size, self.hidden_size, self.num_layers = embed_size, hidden_size, num_layers
        self.encoder = nn.Sequential(nn.Linear(input_size, embed_size), nn.ReLU())
        self.gru = nn.GRU(input_size=embed_size, hidden_size=hidden_size, num_layers=num_layers, batch_first=True,
                          dropout=dropout_rate if num_layers > 1 else 0.0)
        self.dropout = nn.Dropout(dropout_rate)
        self.fc = nn.Linear(hidden_size, 1)

    def forward(self, x):
        """x: (B, max_views, C) scaled token matrices with column 0 = valid; returns (B, 1) logits."""
        h = self.encoder(x) * x[..., :1]
        out, _hidden = self.gru(h)
        return self.fc(self.dropout(out[:, -1, :]))
