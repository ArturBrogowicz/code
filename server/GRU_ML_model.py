import torch
import torch.nn as nn


class GRUDDoSClassifier(nn.Module):
    """
    Gated Recurrent Unit (GRU) classifier designed for DDoS attack detection.
    
    """

    def __init__(self, input_size, hidden_size, num_layers, output_size=1, dropout_rate=0.2):
        """
        Initializes the GRUDDoSClassifier model.

        Parameters:
        -----------
        input_size : int
            The number of expected features in the input x (e.g., request time, length, bytes sent).
        hidden_size : int
            The number of features in the hidden state h of the GRU layer.
        num_layers : int
            Number of recurrent layers stacked on top of each other (Deep RNN).
        output_size : int, optional
            The number of output units. Defaults to 1 for binary classification.
        dropout_rate : float, optional
            The dropout probability for regularization between GRU layers. Defaults to 0.2.
        """
        super(GRUDDoSClassifier, self).__init__()

        self.hidden_size = hidden_size
        self.num_layers = num_layers

        self.gru = nn.GRU(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout_rate if num_layers > 1 else 0
        )

        self.dropout = nn.Dropout(dropout_rate)
        self.fc = nn.Linear(hidden_size, output_size)

    def forward(self, x):
        """
        Performs the forward pass of the model.

        Parameters:
        -----------
        x : torch.Tensor
            Input tensor of shape (batch_size, sequence_length, input_size).

        Returns:
        --------
        torch.Tensor
            Output logits of shape (batch_size, output_size).
        """
        h0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size).to(x.device)

        out, _hidden = self.gru(x, h0)
        out = out[:, -1, :]
        out = self.dropout(out)
        out = self.fc(out)

        return out